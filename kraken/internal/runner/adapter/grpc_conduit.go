package adapter

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"bytemomo/kraken/internal/domain"
	"bytemomo/kraken/internal/runner/contextkeys"
	"bytemomo/kraken/internal/transport"
	"bytemomo/kraken/pkg/modulepb"

	cnd "bytemomo/trident/conduit"
	"bytemomo/trident/conduit/utils"

	"google.golang.org/protobuf/types/known/structpb"
)

// connEntry tracks a single multiplexed conduit connection.
type connEntry struct {
	id      uint32
	kind    cnd.Kind
	conduit interface{} // cnd.Stream, cnd.Datagram, or cnd.Frame
	cleanup func()
	stack   []string
	closed  bool
}

// connTable manages multiplexed connections for a single RunWithConduit session.
type connTable struct {
	mu      sync.Mutex
	entries map[uint32]*connEntry
	nextID  uint32
}

func newConnTable() *connTable {
	return &connTable{entries: make(map[uint32]*connEntry)}
}

// Add registers a new connection and returns its assigned ID.
func (ct *connTable) Add(kind cnd.Kind, conduit interface{}, cleanup func(), stack []string) uint32 {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	id := ct.nextID
	ct.nextID++
	ct.entries[id] = &connEntry{
		id: id, kind: kind, conduit: conduit, cleanup: cleanup, stack: stack,
	}
	return id
}

// Get returns the entry for the given ID, or nil if not found/closed.
func (ct *connTable) Get(id uint32) *connEntry {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	e := ct.entries[id]
	if e != nil && e.closed {
		return nil
	}
	return e
}

// Close marks an entry as closed and runs its cleanup. Returns an error if unknown/already closed.
func (ct *connTable) Close(id uint32) error {
	ct.mu.Lock()
	e := ct.entries[id]
	if e == nil {
		ct.mu.Unlock()
		return fmt.Errorf("unknown connection: %d", id)
	}
	if e.closed {
		ct.mu.Unlock()
		return fmt.Errorf("connection %d already closed", id)
	}
	e.closed = true
	ct.mu.Unlock()

	if e.cleanup != nil {
		e.cleanup()
	}
	return nil
}

// CloseAll closes every open connection.
func (ct *connTable) CloseAll() {
	ct.mu.Lock()
	entries := make([]*connEntry, 0, len(ct.entries))
	for _, e := range ct.entries {
		if !e.closed {
			e.closed = true
			entries = append(entries, e)
		}
	}
	ct.mu.Unlock()

	for _, e := range entries {
		if e.cleanup != nil {
			e.cleanup()
		}
	}
}

// runWithConduit executes a gRPC module via the RunWithConduit bidirectional stream,
// proxying conduit I/O so the module does not manage transport.
func runWithConduit(
	ctx context.Context,
	client modulepb.KrakenModuleClient,
	timeoutMs uint32,
	params map[string]*structpb.Value,
	target domain.Target,
	initialConduit interface{},
	initialCleanup func(),
	initialKind cnd.Kind,
	initialStack []string,
	factory contextkeys.ConduitFactoryFunc,
) (domain.RunResult, error) {
	ct := newConnTable()
	defer ct.CloseAll()

	// Register the pre-dialed initial connection as conn_id=0.
	conn0ID := ct.Add(initialKind, initialConduit, initialCleanup, initialStack)
	conn0Info := buildConnInfo(conn0ID, initialKind, initialStack, initialConduit)

	stream, err := client.RunWithConduit(ctx)
	if err != nil {
		return domain.RunResult{Target: target}, fmt.Errorf("open RunWithConduit stream: %w", err)
	}

	// Send the init message with timeout, params, and the pre-dialed connection.
	if err := stream.Send(&modulepb.RunnerMsg{
		Msg: &modulepb.RunnerMsg_Init{
			Init: &modulepb.ConduitInit{
				TimeoutMs: timeoutMs,
				Params:    params,
				Conn:      conn0Info,
			},
		},
	}); err != nil {
		return domain.RunResult{Target: target}, fmt.Errorf("send conduit init: %w", err)
	}

	// Dispatch loop: read commands from module, execute on conduit, send responses.
	for {
		msg, err := stream.Recv()
		if err != nil {
			return domain.RunResult{Target: target}, fmt.Errorf("recv from module stream: %w", err)
		}

		switch m := msg.Msg.(type) {
		case *modulepb.ModuleMsg_Command:
			resp, err := dispatchCommand(ctx, ct, m.Command, factory)
			if err != nil {
				// Fatal dispatch error — notify module and abort.
				_ = stream.Send(&modulepb.RunnerMsg{
					Msg: &modulepb.RunnerMsg_StreamError{
						StreamError: &modulepb.RunnerError{Message: err.Error()},
					},
				})
				return domain.RunResult{Target: target}, err
			}
			if err := stream.Send(resp); err != nil {
				return domain.RunResult{Target: target}, fmt.Errorf("send response seq=%d: %w", m.Command.Seq, err)
			}

		case *modulepb.ModuleMsg_Done:
			return convertRunResponse(m.Done.GetResponse(), target), nil

		default:
			return domain.RunResult{Target: target}, fmt.Errorf("unexpected module message type: %T", msg.Msg)
		}
	}
}

// dispatchCommand executes a single conduit command and returns the response.
func dispatchCommand(
	ctx context.Context,
	ct *connTable,
	cmd *modulepb.ConduitCommand,
	factory contextkeys.ConduitFactoryFunc,
) (*modulepb.RunnerMsg, error) {
	seq := cmd.Seq

	switch op := cmd.Op.(type) {
	case *modulepb.ConduitCommand_Send:
		return dispatchSend(ctx, ct, seq, op.Send)
	case *modulepb.ConduitCommand_Recv:
		return dispatchRecv(ctx, ct, seq, op.Recv)
	case *modulepb.ConduitCommand_Open:
		return dispatchOpen(ctx, ct, seq, op.Open, factory)
	case *modulepb.ConduitCommand_Close:
		return dispatchClose(ct, seq, op.Close)
	default:
		return nil, fmt.Errorf("unknown command op type: %T", cmd.Op)
	}
}

func dispatchSend(ctx context.Context, ct *connTable, seq uint64, cmd *modulepb.SendCmd) (*modulepb.RunnerMsg, error) {
	entry := ct.Get(cmd.ConnId)
	if entry == nil {
		return sendResponse(seq, &modulepb.SendResult{Error: fmt.Sprintf("unknown or closed connection: %d", cmd.ConnId)}), nil
	}

	n, err := executeSend(ctx, entry, cmd.Data)
	result := &modulepb.SendResult{BytesWritten: int32(n)}
	if err != nil {
		result.Error = err.Error()
	}
	return sendResponse(seq, result), nil
}

func dispatchRecv(ctx context.Context, ct *connTable, seq uint64, cmd *modulepb.RecvCmd) (*modulepb.RunnerMsg, error) {
	entry := ct.Get(cmd.ConnId)
	if entry == nil {
		return recvResponse(seq, &modulepb.RecvResult{Error: fmt.Sprintf("unknown or closed connection: %d", cmd.ConnId)}), nil
	}

	data, eof, err := executeRecv(ctx, entry, cmd.TimeoutMs, cmd.MaxBytes)
	result := &modulepb.RecvResult{Data: data, Eof: eof}
	if err != nil {
		result.Error = err.Error()
	}
	return recvResponse(seq, result), nil
}

func dispatchOpen(ctx context.Context, ct *connTable, seq uint64, cmd *modulepb.OpenCmd, factory contextkeys.ConduitFactoryFunc) (*modulepb.RunnerMsg, error) {
	if factory == nil {
		return openResponse(seq, &modulepb.OpenResult{Error: "no conduit factory available"}), nil
	}

	timeout := time.Duration(cmd.TimeoutMs) * time.Millisecond
	if timeout == 0 {
		timeout = 10 * time.Second
	}

	conduit, cleanup, stack, err := factory(timeout)
	if err != nil {
		return openResponse(seq, &modulepb.OpenResult{Error: fmt.Sprintf("dial: %s", err)}), nil
	}

	kind := kindFromConduit(conduit)
	id := ct.Add(kind, conduit, cleanup, stack)
	info := buildConnInfo(id, kind, stack, conduit)

	return openResponse(seq, &modulepb.OpenResult{Conn: info}), nil
}

func dispatchClose(ct *connTable, seq uint64, cmd *modulepb.CloseCmd) (*modulepb.RunnerMsg, error) {
	err := ct.Close(cmd.ConnId)
	result := &modulepb.CloseResult{}
	if err != nil {
		result.Error = err.Error()
	}
	return closeResponse(seq, result), nil
}

// executeSend sends data on the conduit, dispatching by kind.
func executeSend(ctx context.Context, entry *connEntry, data []byte) (int, error) {
	switch c := entry.conduit.(type) {
	case cnd.Stream:
		n, _, err := c.Send(ctx, data, nil, &cnd.SendOptions{})
		return n, err
	case cnd.Datagram:
		buf := utils.GetBuf(len(data))
		copy(buf.Bytes(), data)
		msg := &cnd.DatagramMsg{Data: buf}
		n, _, err := c.Send(ctx, msg, &cnd.SendOptions{})
		return n, err
	case cnd.Frame:
		buf := utils.GetBuf(len(data))
		copy(buf.Bytes(), data)
		pkt := &cnd.FramePkt{
			Data:      buf,
			Dst:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
			EtherType: 0x88A4,
		}
		n, _, err := c.Send(ctx, pkt, &cnd.SendOptions{})
		return n, err
	default:
		return 0, fmt.Errorf("unsupported conduit type: %T", entry.conduit)
	}
}

// executeRecv reads data from the conduit, dispatching by kind.
func executeRecv(ctx context.Context, entry *connEntry, timeoutMs uint32, maxBytes uint32) ([]byte, bool, error) {
	if timeoutMs > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(timeoutMs)*time.Millisecond)
		defer cancel()
	}
	if maxBytes == 0 {
		maxBytes = 65536
	}

	switch c := entry.conduit.(type) {
	case cnd.Stream:
		chunk, err := c.Recv(ctx, &cnd.RecvOptions{MaxBytes: int(maxBytes)})
		if err == io.EOF {
			return nil, true, nil
		}
		if err != nil {
			return nil, false, err
		}
		if chunk == nil || chunk.Data == nil {
			return nil, true, nil
		}
		data := make([]byte, len(chunk.Data.Bytes()))
		copy(data, chunk.Data.Bytes())
		chunk.Data.Release()
		return data, false, nil

	case cnd.Datagram:
		msg, err := c.Recv(ctx, &cnd.RecvOptions{MaxBytes: int(maxBytes)})
		if err == io.EOF {
			return nil, true, nil
		}
		if err != nil {
			return nil, false, err
		}
		if msg == nil || msg.Data == nil {
			return nil, true, nil
		}
		data := make([]byte, len(msg.Data.Bytes()))
		copy(data, msg.Data.Bytes())
		msg.Data.Release()
		return data, false, nil

	case cnd.Frame:
		pkt, err := c.Recv(ctx, nil)
		if err == io.EOF {
			return nil, true, nil
		}
		if err != nil {
			return nil, false, err
		}
		if pkt == nil || pkt.Data == nil {
			return nil, true, nil
		}
		data := make([]byte, len(pkt.Data.Bytes()))
		copy(data, pkt.Data.Bytes())
		pkt.Data.Release()
		return data, false, nil

	default:
		return nil, false, fmt.Errorf("unsupported conduit type: %T", entry.conduit)
	}
}

// buildConnInfo creates a ConnInfo proto from a conduit entry.
func buildConnInfo(id uint32, kind cnd.Kind, stack []string, conduit interface{}) *modulepb.ConnInfo {
	info := &modulepb.ConnInfo{
		ConnId: id,
		Kind:   conduitKindToProto(kind),
		Stack:  stack,
	}
	switch c := conduit.(type) {
	case cnd.Stream:
		if c.LocalAddr() != nil {
			info.LocalAddr = c.LocalAddr().String()
		}
		if c.RemoteAddr() != nil {
			info.RemoteAddr = c.RemoteAddr().String()
		}
	case cnd.Datagram:
		if c.LocalAddr().IsValid() {
			info.LocalAddr = c.LocalAddr().String()
		}
		if c.RemoteAddr().IsValid() {
			info.RemoteAddr = c.RemoteAddr().String()
		}
	case cnd.Frame:
		if c.Interface() != nil {
			info.LocalAddr = c.Interface().Name
		}
	}
	return info
}

func conduitKindToProto(k cnd.Kind) modulepb.ConduitKind {
	switch k {
	case cnd.KindStream:
		return modulepb.ConduitKind_CONDUIT_KIND_STREAM
	case cnd.KindDatagram:
		return modulepb.ConduitKind_CONDUIT_KIND_DATAGRAM
	case cnd.KindFrame:
		return modulepb.ConduitKind_CONDUIT_KIND_FRAME
	default:
		return modulepb.ConduitKind_CONDUIT_KIND_UNSPECIFIED
	}
}

func kindFromConduit(c interface{}) cnd.Kind {
	switch c.(type) {
	case cnd.Stream:
		return cnd.KindStream
	case cnd.Datagram:
		return cnd.KindDatagram
	case cnd.Frame:
		return cnd.KindFrame
	default:
		return cnd.KindUnknown
	}
}

// convertRunResponse converts a proto RunResponse to a domain.RunResult.
func convertRunResponse(resp *modulepb.RunResponse, target domain.Target) domain.RunResult {
	result := domain.RunResult{Target: target}
	if resp == nil {
		return result
	}
	for _, f := range resp.GetFindings() {
		ev := map[string]any{}
		for k, v := range f.GetEvidence() {
			ev[k] = v
		}
		var tags []domain.Tag
		for _, s := range f.GetTags() {
			tags = append(tags, domain.Tag(s))
		}
		result.Findings = append(result.Findings, domain.Finding{
			ID: f.GetId(), ModuleID: f.GetModuleId(), Title: f.GetTitle(),
			Severity: f.GetSeverity(), Description: f.GetDescription(),
			Evidence: ev, Tags: tags, Target: target, Success: f.Success,
			Timestamp: time.Unix(f.GetTimestamp(), 0).UTC(),
		})
	}
	for _, l := range resp.GetLogs() {
		result.Logs = append(result.Logs, l.GetLine())
	}
	return result
}

// Response builder helpers.

func sendResponse(seq uint64, r *modulepb.SendResult) *modulepb.RunnerMsg {
	return &modulepb.RunnerMsg{
		Msg: &modulepb.RunnerMsg_Response{
			Response: &modulepb.ConduitResponse{
				Seq:    seq,
				Result: &modulepb.ConduitResponse_SendResult{SendResult: r},
			},
		},
	}
}

func recvResponse(seq uint64, r *modulepb.RecvResult) *modulepb.RunnerMsg {
	return &modulepb.RunnerMsg{
		Msg: &modulepb.RunnerMsg_Response{
			Response: &modulepb.ConduitResponse{
				Seq:    seq,
				Result: &modulepb.ConduitResponse_RecvResult{RecvResult: r},
			},
		},
	}
}

func openResponse(seq uint64, r *modulepb.OpenResult) *modulepb.RunnerMsg {
	return &modulepb.RunnerMsg{
		Msg: &modulepb.RunnerMsg_Response{
			Response: &modulepb.ConduitResponse{
				Seq:    seq,
				Result: &modulepb.ConduitResponse_OpenResult{OpenResult: r},
			},
		},
	}
}

func closeResponse(seq uint64, r *modulepb.CloseResult) *modulepb.RunnerMsg {
	return &modulepb.RunnerMsg{
		Msg: &modulepb.RunnerMsg_Response{
			Response: &modulepb.ConduitResponse{
				Seq:    seq,
				Result: &modulepb.ConduitResponse_CloseResult{CloseResult: r},
			},
		},
	}
}

// buildConduitFactory creates a conduit factory for the gRPC conduit adapter,
// following the same pattern as the ABI adapter.
func buildConduitFactory(ctx context.Context, t domain.Target, cfg *domain.Module) (contextkeys.ConduitFactoryFunc, cnd.Kind, error) {
	if cfg.ExecConfig.Conduit == nil {
		return nil, 0, fmt.Errorf("conduit config required for RunWithConduit")
	}

	conduitCfg := cfg.ExecConfig.Conduit
	kind := conduitCfg.Kind
	dialOpts := dialOptionsFromCtx(ctx)

	switch target := t.(type) {
	case domain.HostPort:
		addr := fmt.Sprintf("%s:%d", target.Host, target.Port)
		factory := buildGRPCNetworkConduitFactory(addr, kind, conduitCfg.Stack, dialOpts)
		return factory, kind, nil
	case domain.EtherCATMaster:
		if kind != cnd.KindFrame {
			return nil, 0, fmt.Errorf("EtherCAT targets require KindFrame conduit, got %v", kind)
		}
		factory := buildGRPCFrameConduitFactory(target.Interface, dialOpts)
		return factory, kind, nil
	default:
		return nil, 0, fmt.Errorf("unsupported target type: %T", t)
	}
}

func dialOptionsFromCtx(ctx context.Context) transport.DialOptions {
	if v := ctx.Value(contextkeys.ConnectionDefaults); v != nil {
		if defaults, ok := v.(*domain.ConnectionDefaults); ok {
			return transport.DialOptionsFromDefaults(defaults)
		}
	}
	return transport.DefaultDialOptions()
}

func buildGRPCNetworkConduitFactory(addr string, kind cnd.Kind, stack []domain.LayerHint, dialOpts transport.DialOptions) contextkeys.ConduitFactoryFunc {
	return func(timeout time.Duration) (interface{}, func(), []string, error) {
		dialCtx := context.Background()
		if timeout > 0 {
			var cancel context.CancelFunc
			dialCtx, cancel = context.WithTimeout(context.Background(), timeout)
			defer cancel()
		}

		layers := make([]string, 0, len(stack))
		for _, l := range stack {
			layers = append(layers, l.Name)
		}

		switch kind {
		case cnd.KindStream:
			if err := transport.AcquireConnSlot(dialCtx, dialOpts.ConnSem); err != nil {
				return nil, nil, nil, err
			}
			c, err := transport.BuildStreamConduit(addr, stack)
			if err != nil {
				transport.ReleaseConnSlot(dialOpts.ConnSem)
				return nil, nil, nil, err
			}
			if err := transport.DialWithRetry(dialCtx, c, dialOpts); err != nil {
				c.Close()
				transport.ReleaseConnSlot(dialOpts.ConnSem)
				return nil, nil, nil, err
			}
			return c.Underlying(), func() {
				c.Close()
				transport.ReleaseConnSlot(dialOpts.ConnSem)
			}, layers, nil

		case cnd.KindDatagram:
			if err := transport.AcquireConnSlot(dialCtx, dialOpts.ConnSem); err != nil {
				return nil, nil, nil, err
			}
			c, err := transport.BuildDatagramConduit(addr, stack)
			if err != nil {
				transport.ReleaseConnSlot(dialOpts.ConnSem)
				return nil, nil, nil, err
			}
			if err := transport.DialWithRetry(dialCtx, c, dialOpts); err != nil {
				c.Close()
				transport.ReleaseConnSlot(dialOpts.ConnSem)
				return nil, nil, nil, err
			}
			return c.Underlying(), func() {
				c.Close()
				transport.ReleaseConnSlot(dialOpts.ConnSem)
			}, layers, nil

		default:
			return nil, nil, nil, fmt.Errorf("unsupported conduit kind for network target: %v", kind)
		}
	}
}

func buildGRPCFrameConduitFactory(iface string, dialOpts transport.DialOptions) contextkeys.ConduitFactoryFunc {
	return func(timeout time.Duration) (interface{}, func(), []string, error) {
		dialCtx := context.Background()
		if timeout > 0 {
			var cancel context.CancelFunc
			dialCtx, cancel = context.WithTimeout(context.Background(), timeout)
			defer cancel()
		}

		if err := transport.AcquireConnSlot(dialCtx, dialOpts.ConnSem); err != nil {
			return nil, nil, nil, err
		}
		c := transport.BuildEtherCATConduit(iface)
		if err := transport.DialWithRetry(dialCtx, c, dialOpts); err != nil {
			c.Close()
			transport.ReleaseConnSlot(dialOpts.ConnSem)
			return nil, nil, nil, err
		}
		return c.Underlying(), func() {
			c.Close()
			transport.ReleaseConnSlot(dialOpts.ConnSem)
		}, []string{"eth"}, nil
	}
}


