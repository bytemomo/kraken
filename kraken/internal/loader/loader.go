package loader

import (
	"context"
	"io"
	"net"
	"sync"
	"time"
	"unsafe"

	"bytemomo/kraken/internal/domain"
	"bytemomo/kraken/internal/runner/contextkeys"

	cnd "bytemomo/trident/conduit"
	utils "bytemomo/trident/conduit/utils"
)

/*
#include <stdlib.h>
#include <string.h>
#include "../../pkg/moduleabi/kraken_module_abi.h"
#include "../../pkg/moduleabi/kraken_module_abi_v2.h"
*/
import "C"

// LoadableModule is an interface for a loadable native module.
type LoadableModule interface {
	// Run runs the module.
	Run(ctx context.Context, params map[string]any, t domain.Target, timeout time.Duration, conduit interface{}) (domain.RunResult, error)
	// Close closes the module.
	Close() error
}

type v2ConduitFactory = contextkeys.ConduitFactoryFunc

type v2ConnectionHandle struct {
	conduit     interface{}
	info        *C.KrakenConnectionInfo
	close       func()
	factory     v2ConduitFactory
	stackLayers []string
	children    []uintptr
}

var (
	v2HandleMap             = make(map[uintptr]*v2ConnectionHandle)
	v2HandleCounter uintptr = 1
	v2HandleMutex   sync.RWMutex
)

// buildConnectionInfo allocates a KrakenConnectionInfo for the provided conduit.
func buildConnectionInfo(conduit interface{}, stackLayers []string, defaultRemote string) *C.KrakenConnectionInfo {
	info := (*C.KrakenConnectionInfo)(C.malloc(C.sizeof_KrakenConnectionInfo))
	info.remote_addr = C.CString(defaultRemote)
	info.local_addr = C.CString("0.0.0.0:0")

	layers := stackLayers

	switch c := conduit.(type) {
	case cnd.Stream:
		*(*C.KrakenConnectionType)(unsafe.Pointer(info)) = C.KRAKEN_CONN_TYPE_STREAM
		if c.LocalAddr() != nil {
			C.free(unsafe.Pointer(info.local_addr))
			info.local_addr = C.CString(c.LocalAddr().String())
		}
		if c.RemoteAddr() != nil {
			C.free(unsafe.Pointer(info.remote_addr))
			info.remote_addr = C.CString(c.RemoteAddr().String())
		}
		if len(layers) == 0 {
			layers = []string{"tcp"}
		}
	case cnd.Datagram:
		*(*C.KrakenConnectionType)(unsafe.Pointer(info)) = C.KRAKEN_CONN_TYPE_DATAGRAM
		if c.LocalAddr().IsValid() {
			C.free(unsafe.Pointer(info.local_addr))
			info.local_addr = C.CString(c.LocalAddr().String())
		}
		if c.RemoteAddr().IsValid() {
			C.free(unsafe.Pointer(info.remote_addr))
			info.remote_addr = C.CString(c.RemoteAddr().String())
		}
		if len(layers) == 0 {
			layers = []string{"udp"}
		}
	default:
		*(*C.KrakenConnectionType)(unsafe.Pointer(info)) = C.KRAKEN_CONN_TYPE_STREAM
		if len(layers) == 0 {
			layers = []string{"tcp"}
		}
	}

	info.stack_layers_count = C.size_t(len(layers))
	info.stack_layers = (**C.char)(C.malloc(C.size_t(len(layers)) * C.sizeof_uintptr_t))
	for i, layer := range layers {
		layerPtr := (**C.char)(unsafe.Pointer(uintptr(unsafe.Pointer(info.stack_layers)) + uintptr(i)*unsafe.Sizeof(uintptr(0))))
		*layerPtr = C.CString(layer)
	}

	return info
}

func freeConnectionInfo(info *C.KrakenConnectionInfo, stackLayers []string) {
	if info == nil {
		return
	}
	C.free(unsafe.Pointer(info.remote_addr))
	C.free(unsafe.Pointer(info.local_addr))
	for i := 0; i < len(stackLayers); i++ {
		layerPtr := (**C.char)(unsafe.Pointer(uintptr(unsafe.Pointer(info.stack_layers)) + uintptr(i)*unsafe.Sizeof(uintptr(0))))
		C.free(unsafe.Pointer(*layerPtr))
	}
	C.free(unsafe.Pointer(info.stack_layers))
	C.free(unsafe.Pointer(info))
}

//export go_conduit_send
func go_conduit_send(conn C.KrakenConnectionHandle, data *C.uint8_t, length C.size_t, timeout_ms C.uint32_t) C.int64_t {
	v2HandleMutex.RLock()
	handle, ok := v2HandleMap[uintptr(conn)]
	v2HandleMutex.RUnlock()

	if !ok {
		return -1
	}

	goData := C.GoBytes(unsafe.Pointer(data), C.int(length))

	switch c := handle.conduit.(type) {
	case cnd.Stream:
		ctx := context.Background()
		if timeout_ms > 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, time.Duration(timeout_ms)*time.Millisecond)
			defer cancel()
		}

		n, _, err := c.Send(ctx, goData, nil, &cnd.SendOptions{})
		if err != nil {
			return -1
		}
		return C.int64_t(n)

	case cnd.Datagram:
		ctx := context.Background()
		if timeout_ms > 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, time.Duration(timeout_ms)*time.Millisecond)
			defer cancel()
		}

		buf := utils.GetBuf(len(goData))
		copy(buf.Bytes(), goData)
		msg := &cnd.DatagramMsg{
			Data: buf,
		}
		n, _, err := c.Send(ctx, msg, &cnd.SendOptions{})
		if err != nil {
			return -1
		}
		return C.int64_t(n)

	case cnd.Frame:
		ctx := context.Background()
		if timeout_ms > 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, time.Duration(timeout_ms)*time.Millisecond)
			defer cancel()
		}

		// For Frame, the data should be the full Ethernet payload (after header)
		// The module sends EtherCAT data; we need to wrap it in a FramePkt
		buf := utils.GetBuf(len(goData))
		copy(buf.Bytes(), goData)

		// Use broadcast destination for EtherCAT
		pkt := &cnd.FramePkt{
			Data:      buf,
			Dst:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
			EtherType: 0x88A4, // EtherCAT
		}

		n, _, err := c.Send(ctx, pkt, &cnd.SendOptions{})
		if err != nil {
			return -1
		}
		return C.int64_t(n)

	default:
		return -1
	}
}

//export go_conduit_recv
func go_conduit_recv(conn C.KrakenConnectionHandle, buffer *C.uint8_t, buffer_size C.size_t, timeout_ms C.uint32_t) C.int64_t {
	v2HandleMutex.RLock()
	handle, ok := v2HandleMap[uintptr(conn)]
	v2HandleMutex.RUnlock()

	if !ok {
		return -1
	}

	switch c := handle.conduit.(type) {
	case cnd.Stream:
		ctx := context.Background()
		if timeout_ms > 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, time.Duration(timeout_ms)*time.Millisecond)
			defer cancel()
		}

		maxBytes := int(buffer_size)
		if maxBytes == 0 {
			maxBytes = 4096
		}

		chunk, err := c.Recv(ctx, &cnd.RecvOptions{MaxBytes: maxBytes})
		if err == io.EOF {
			return 0
		} else if err != nil {
			return -1
		}

		if chunk != nil && chunk.Data != nil {
			data := chunk.Data.Bytes()
			n := len(data)
			if n > int(buffer_size) {
				n = int(buffer_size)
			}
			C.memcpy(unsafe.Pointer(buffer), unsafe.Pointer(&data[0]), C.size_t(n))
			chunk.Data.Release()
			return C.int64_t(n)
		}
		return 0

	case cnd.Datagram:
		ctx := context.Background()
		if timeout_ms > 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, time.Duration(timeout_ms)*time.Millisecond)
			defer cancel()
		}

		maxBytes := int(buffer_size)
		if maxBytes == 0 {
			maxBytes = 4096
		}

		chunk, err := c.Recv(ctx, &cnd.RecvOptions{MaxBytes: maxBytes})
		if err == io.EOF {
			return 0
		} else if err != nil {
			return -1
		}

		if chunk != nil && chunk.Data != nil {
			data := chunk.Data.Bytes()
			n := len(data)
			if n > int(buffer_size) {
				n = int(buffer_size)
			}
			C.memcpy(unsafe.Pointer(buffer), unsafe.Pointer(&data[0]), C.size_t(n))
			chunk.Data.Release()
			return C.int64_t(n)
		}
		return 0

	case cnd.Frame:
		ctx := context.Background()
		if timeout_ms > 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, time.Duration(timeout_ms)*time.Millisecond)
			defer cancel()
		}

		pkt, err := c.Recv(ctx, nil)
		if err == io.EOF {
			return 0
		} else if err != nil {
			return -1
		}

		if pkt != nil && pkt.Data != nil {
			data := pkt.Data.Bytes()
			n := len(data)
			if n > int(buffer_size) {
				n = int(buffer_size)
			}
			C.memcpy(unsafe.Pointer(buffer), unsafe.Pointer(&data[0]), C.size_t(n))
			pkt.Data.Release()
			return C.int64_t(n)
		}
		return 0

	default:
		return -1
	}
}

//export go_conduit_get_info
func go_conduit_get_info(conn C.KrakenConnectionHandle) *C.KrakenConnectionInfo {
	v2HandleMutex.RLock()
	handle, ok := v2HandleMap[uintptr(conn)]
	v2HandleMutex.RUnlock()

	if !ok {
		return nil
	}
	return handle.info
}

//export go_conduit_open
func go_conduit_open(conn C.KrakenConnectionHandle, timeout_ms C.uint32_t) C.KrakenConnectionHandle {
	v2HandleMutex.RLock()
	parent, ok := v2HandleMap[uintptr(conn)]
	v2HandleMutex.RUnlock()
	if !ok || parent.factory == nil {
		return nil
	}

	timeout := time.Duration(timeout_ms) * time.Millisecond
	conduit, closeFn, layers, err := parent.factory(timeout)
	if err != nil {
		return nil
	}
	if len(layers) == 0 {
		layers = parent.stackLayers
	}

	info := buildConnectionInfo(conduit, layers, C.GoString(parent.info.remote_addr))

	v2HandleMutex.Lock()
	handleID := v2HandleCounter
	v2HandleCounter++
	v2HandleMap[handleID] = &v2ConnectionHandle{conduit: conduit, info: info, close: closeFn, factory: parent.factory, stackLayers: layers}
	parent.children = append(parent.children, handleID)
	v2HandleMutex.Unlock()

	return C.KrakenConnectionHandle(unsafe.Pointer(handleID))
}

//export go_conduit_close
func go_conduit_close(conn C.KrakenConnectionHandle) {
	id := uintptr(conn)
	v2HandleMutex.Lock()
	handle, ok := v2HandleMap[id]
	if ok {
		delete(v2HandleMap, id)
	}
	v2HandleMutex.Unlock()

	if !ok {
		return
	}

	if handle.close != nil {
		handle.close()
	}
	freeConnectionInfo(handle.info, handle.stackLayers)
}

func decodeRunResult(cResult *C.KrakenRunResult) (domain.RunResult, error) {
	var res domain.RunResult
	res.Target = domain.HostPort{
		Host: C.GoString(cResult.target.host),
		Port: uint16(cResult.target.port),
	}

	if cResult.logs.count > 0 {
		logSlice := unsafe.Slice(cResult.logs.strings, cResult.logs.count)
		for _, s := range logSlice {
			res.Logs = append(res.Logs, C.GoString(s))
		}
	}

	if cResult.findings_count > 0 {
		findingSlice := unsafe.Slice(cResult.findings, cResult.findings_count)
		for _, cFinding := range findingSlice {
			ev := make(map[string]any)
			if cFinding.evidence.count > 0 {
				evidenceSlice := unsafe.Slice(cFinding.evidence.items, cFinding.evidence.count)
				for _, kv := range evidenceSlice {
					ev[C.GoString(kv.key)] = C.GoString(kv.value)
				}
			}

			var tags []domain.Tag
			if cFinding.tags.count > 0 {
				tagSlice := unsafe.Slice(cFinding.tags.strings, cFinding.tags.count)
				for _, s := range tagSlice {
					tags = append(tags, domain.Tag(C.GoString(s)))
				}
			}

			findingTarget := domain.HostPort{
				Host: C.GoString(cFinding.target.host),
				Port: uint16(cFinding.target.port),
			}

			var timestamp time.Time
			if cFinding.timestamp != 0 {
				timestamp = time.Unix(int64(cFinding.timestamp), 0).UTC()
			} else {
				timestamp = time.Now()
			}

			res.Findings = append(res.Findings, domain.Finding{
				ID:          C.GoString(cFinding.id),
				ModuleID:    C.GoString(cFinding.module_id),
				Success:     bool(cFinding.success),
				Title:       C.GoString(cFinding.title),
				Severity:    C.GoString(cFinding.severity),
				Description: C.GoString(cFinding.description),
				Evidence:    ev,
				Tags:        tags,
				Timestamp:   timestamp,
				Target:      findingTarget,
			})
		}
	}

	return res, nil
}

func decodeTarget(cTarget *C.KrakenTarget) domain.Target {
	switch cTarget.kind {
	case C.KRAKEN_TARGET_KIND_NETWORK:
		network := (*C.KrakenHostPort)(unsafe.Pointer(&cTarget.u[0]))
		return domain.HostPort{
			Host: C.GoString(network.host),
			Port: uint16(network.port),
		}
	case C.KRAKEN_TARGET_KIND_ETHERCAT:
		ethercat := (*C.KrakenEtherCATTarget)(unsafe.Pointer(&cTarget.u[0]))
		mac, _ := net.ParseMAC(C.GoString(ethercat.mac_address))
		var slaves []uint16
		if ethercat.slaves_len > 0 {
			slaves = make([]uint16, ethercat.slaves_len)
			cSlaves := unsafe.Slice(ethercat.slaves, ethercat.slaves_len)
			for i, s := range cSlaves {
				slaves[i] = uint16(s)
			}
		}
		return domain.EtherCATMaster{
			Interface:  C.GoString(ethercat.iface),
			MACAddress: mac,
			SlaveCount: int(ethercat.slave_count),
			Slaves:     slaves,
		}
	default:
		return domain.HostPort{}
	}
}

func decodeRunResultV2(cResult *C.KrakenRunResultV2) (domain.RunResult, error) {
	var res domain.RunResult
	res.Target = decodeTarget(&cResult.target)

	if cResult.logs.count > 0 {
		logSlice := unsafe.Slice(cResult.logs.strings, cResult.logs.count)
		for _, s := range logSlice {
			res.Logs = append(res.Logs, C.GoString(s))
		}
	}

	if cResult.findings_count > 0 {
		findingSlice := unsafe.Slice(cResult.findings, cResult.findings_count)
		for _, cFinding := range findingSlice {
			ev := make(map[string]any)
			if cFinding.evidence.count > 0 {
				evidenceSlice := unsafe.Slice(cFinding.evidence.items, cFinding.evidence.count)
				for _, kv := range evidenceSlice {
					ev[C.GoString(kv.key)] = C.GoString(kv.value)
				}
			}

			var tags []domain.Tag
			if cFinding.tags.count > 0 {
				tagSlice := unsafe.Slice(cFinding.tags.strings, cFinding.tags.count)
				for _, s := range tagSlice {
					tags = append(tags, domain.Tag(C.GoString(s)))
				}
			}

			findingTarget := decodeTarget(&cFinding.target)

			var timestamp time.Time
			if cFinding.timestamp != 0 {
				timestamp = time.Unix(int64(cFinding.timestamp), 0).UTC()
			} else {
				timestamp = time.Now()
			}

			res.Findings = append(res.Findings, domain.Finding{
				ID:          C.GoString(cFinding.id),
				ModuleID:    C.GoString(cFinding.module_id),
				Success:     bool(cFinding.success),
				Title:       C.GoString(cFinding.title),
				Severity:    C.GoString(cFinding.severity),
				Description: C.GoString(cFinding.description),
				Evidence:    ev,
				Tags:        tags,
				Timestamp:   timestamp,
				Target:      findingTarget,
			})
		}
	}

	return res, nil
}

// cleanupHandle removes the handle and its children, releasing resources.
func cleanupHandle(id uintptr, includeChildren bool) {
	v2HandleMutex.Lock()
	handle, ok := v2HandleMap[id]
	if ok {
		delete(v2HandleMap, id)
	}
	v2HandleMutex.Unlock()

	if !ok {
		return
	}

	if includeChildren {
		for _, child := range handle.children {
			cleanupHandle(child, true)
		}
	}

	if handle.close != nil {
		handle.close()
	}
	freeConnectionInfo(handle.info, handle.stackLayers)
}
