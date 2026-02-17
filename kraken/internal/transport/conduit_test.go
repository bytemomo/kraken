package transport

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"bytemomo/kraken/internal/domain"
	cnd "bytemomo/trident/conduit"
)

func TestDefaultDialOptions(t *testing.T) {
	opts := DefaultDialOptions()

	if opts.Timeout != 10*time.Second {
		t.Errorf("expected Timeout=10s, got %v", opts.Timeout)
	}
	if opts.Backoff != 100*time.Millisecond {
		t.Errorf("expected Backoff=100ms, got %v", opts.Backoff)
	}
	if opts.MaxRetries != 3 {
		t.Errorf("expected MaxRetries=3, got %d", opts.MaxRetries)
	}
}

func TestDialOptionsFromDefaults_Nil(t *testing.T) {
	opts := DialOptionsFromDefaults(nil)

	// Should return defaults
	expected := DefaultDialOptions()
	if opts.Timeout != expected.Timeout {
		t.Errorf("expected Timeout=%v, got %v", expected.Timeout, opts.Timeout)
	}
	if opts.Backoff != expected.Backoff {
		t.Errorf("expected Backoff=%v, got %v", expected.Backoff, opts.Backoff)
	}
	if opts.MaxRetries != expected.MaxRetries {
		t.Errorf("expected MaxRetries=%d, got %d", expected.MaxRetries, opts.MaxRetries)
	}
}

func TestDialOptionsFromDefaults_PartialOverride(t *testing.T) {
	defaults := &domain.ConnectionDefaults{
		ConnectionTimeout: 5 * time.Second,
		// Other fields are zero
	}

	opts := DialOptionsFromDefaults(defaults)

	if opts.Timeout != 5*time.Second {
		t.Errorf("expected Timeout=5s, got %v", opts.Timeout)
	}
	// Should use defaults for unspecified fields
	if opts.Backoff != 100*time.Millisecond {
		t.Errorf("expected default Backoff=100ms, got %v", opts.Backoff)
	}
	if opts.MaxRetries != 3 {
		t.Errorf("expected default MaxRetries=3, got %d", opts.MaxRetries)
	}
}

func TestDialOptionsFromDefaults_FullOverride(t *testing.T) {
	defaults := &domain.ConnectionDefaults{
		ConnectionTimeout: 30 * time.Second,
		ConnectionBackoff: 500 * time.Millisecond,
		MaxReconnects:     5,
	}

	opts := DialOptionsFromDefaults(defaults)

	if opts.Timeout != 30*time.Second {
		t.Errorf("expected Timeout=30s, got %v", opts.Timeout)
	}
	if opts.Backoff != 500*time.Millisecond {
		t.Errorf("expected Backoff=500ms, got %v", opts.Backoff)
	}
	if opts.MaxRetries != 5 {
		t.Errorf("expected MaxRetries=5, got %d", opts.MaxRetries)
	}
}

// mockStreamConduit is a test conduit that tracks dial attempts
type mockStreamConduit struct {
	dialCount  atomic.Int32
	dialErrors []error // errors to return on each dial attempt
	dialDelay  time.Duration
}

func (m *mockStreamConduit) Dial(ctx context.Context) error {
	idx := int(m.dialCount.Add(1)) - 1

	if m.dialDelay > 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(m.dialDelay):
		}
	}

	if idx < len(m.dialErrors) {
		return m.dialErrors[idx]
	}
	return nil
}

func (m *mockStreamConduit) Close() error { return nil }

func (m *mockStreamConduit) Kind() cnd.Kind { return cnd.KindStream }

func (m *mockStreamConduit) Stack() []string { return []string{"mock"} }

func (m *mockStreamConduit) Underlying() any {
	return nil
}

func TestDialWithRetry_Success(t *testing.T) {
	conduit := &mockStreamConduit{
		dialErrors: nil, // no errors - succeeds first try
	}

	opts := DialOptions{
		Timeout:    time.Second,
		Backoff:    10 * time.Millisecond,
		MaxRetries: 3,
	}

	err := DialWithRetry[any](context.Background(), conduit, opts)
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}

	if conduit.dialCount.Load() != 1 {
		t.Errorf("expected 1 dial attempt, got %d", conduit.dialCount.Load())
	}
}

func TestDialWithRetry_FailsThenSucceeds(t *testing.T) {
	conduit := &mockStreamConduit{
		dialErrors: []error{
			errors.New("fail 1"),
			errors.New("fail 2"),
			nil, // success on 3rd try
		},
	}

	opts := DialOptions{
		Timeout:    time.Second,
		Backoff:    10 * time.Millisecond,
		MaxRetries: 3,
	}

	err := DialWithRetry[any](context.Background(), conduit, opts)
	if err != nil {
		t.Fatalf("expected success after retries, got error: %v", err)
	}

	if conduit.dialCount.Load() != 3 {
		t.Errorf("expected 3 dial attempts, got %d", conduit.dialCount.Load())
	}
}

func TestDialWithRetry_ExhaustsRetries(t *testing.T) {
	conduit := &mockStreamConduit{
		dialErrors: []error{
			errors.New("fail 1"),
			errors.New("fail 2"),
			errors.New("fail 3"),
			errors.New("fail 4"),
		},
	}

	opts := DialOptions{
		Timeout:    time.Second,
		Backoff:    10 * time.Millisecond,
		MaxRetries: 3,
	}

	err := DialWithRetry[any](context.Background(), conduit, opts)
	if err == nil {
		t.Fatal("expected error after exhausting retries")
	}

	// Should try 4 times total (1 initial + 3 retries)
	if conduit.dialCount.Load() != 4 {
		t.Errorf("expected 4 dial attempts, got %d", conduit.dialCount.Load())
	}

	if !errors.Is(err, conduit.dialErrors[3]) {
		t.Errorf("expected last error to be wrapped, got: %v", err)
	}
}

func TestDialWithRetry_ZeroRetries(t *testing.T) {
	conduit := &mockStreamConduit{
		dialErrors: []error{errors.New("fail")},
	}

	opts := DialOptions{
		Timeout:    time.Second,
		Backoff:    10 * time.Millisecond,
		MaxRetries: 0, // No retries
	}

	err := DialWithRetry[any](context.Background(), conduit, opts)
	if err == nil {
		t.Fatal("expected error with zero retries")
	}

	if conduit.dialCount.Load() != 1 {
		t.Errorf("expected 1 dial attempt with MaxRetries=0, got %d", conduit.dialCount.Load())
	}
}

func TestDialWithRetry_ContextCancelled(t *testing.T) {
	conduit := &mockStreamConduit{
		dialErrors: []error{
			errors.New("fail 1"),
			errors.New("fail 2"),
		},
	}

	ctx, cancel := context.WithCancel(context.Background())

	opts := DialOptions{
		Timeout:    time.Second,
		Backoff:    100 * time.Millisecond, // Long enough for cancel
		MaxRetries: 5,
	}

	// Cancel after first failure during backoff
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	err := DialWithRetry[any](ctx, conduit, opts)
	if err == nil {
		t.Fatal("expected error when context cancelled")
	}

	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got: %v", err)
	}
}

func TestDialWithRetry_Timeout(t *testing.T) {
	conduit := &mockStreamConduit{
		dialDelay:  500 * time.Millisecond, // Slow dial
		dialErrors: nil,
	}

	opts := DialOptions{
		Timeout:    50 * time.Millisecond, // Short timeout
		Backoff:    10 * time.Millisecond,
		MaxRetries: 1,
	}

	err := DialWithRetry[any](context.Background(), conduit, opts)
	if err == nil {
		t.Fatal("expected timeout error")
	}

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("expected context.DeadlineExceeded in error chain, got: %v", err)
	}
}

func TestDialWithRetry_BackoffApplied(t *testing.T) {
	conduit := &mockStreamConduit{
		dialErrors: []error{
			errors.New("fail 1"),
			nil, // success on retry
		},
	}

	backoff := 50 * time.Millisecond
	opts := DialOptions{
		Timeout:    time.Second,
		Backoff:    backoff,
		MaxRetries: 1,
	}

	start := time.Now()
	err := DialWithRetry[any](context.Background(), conduit, opts)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should have waited at least the backoff duration
	if elapsed < backoff {
		t.Errorf("expected at least %v backoff, elapsed %v", backoff, elapsed)
	}
}

func TestBuildStreamConduit_TCP(t *testing.T) {
	stack := []domain.LayerHint{{Name: "tcp"}}

	conduit, err := BuildStreamConduit("localhost:1883", stack)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if conduit == nil {
		t.Fatal("expected non-nil conduit")
	}
}

func TestBuildStreamConduit_TLS(t *testing.T) {
	stack := []domain.LayerHint{
		{Name: "tcp"},
		{Name: "tls", Params: map[string]any{"skip_verify": true}},
	}

	conduit, err := BuildStreamConduit("localhost:8883", stack)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if conduit == nil {
		t.Fatal("expected non-nil conduit")
	}
}

func TestBuildStreamConduit_EmptyStack(t *testing.T) {
	// Empty stack should default to TCP
	conduit, err := BuildStreamConduit("localhost:1883", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if conduit == nil {
		t.Fatal("expected non-nil conduit")
	}
}

func TestBuildStreamConduit_UnknownLayer(t *testing.T) {
	stack := []domain.LayerHint{{Name: "unknown-protocol"}}

	_, err := BuildStreamConduit("localhost:1883", stack)
	if err == nil {
		t.Fatal("expected error for unknown layer")
	}
}

func TestBuildDatagramConduit_UDP(t *testing.T) {
	stack := []domain.LayerHint{{Name: "udp"}}

	conduit, err := BuildDatagramConduit("localhost:5683", stack)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if conduit == nil {
		t.Fatal("expected non-nil conduit")
	}
}

func TestBuildDatagramConduit_DTLS(t *testing.T) {
	stack := []domain.LayerHint{
		{Name: "udp"},
		{Name: "dtls", Params: map[string]any{"skip_verify": true}},
	}

	conduit, err := BuildDatagramConduit("localhost:5684", stack)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if conduit == nil {
		t.Fatal("expected non-nil conduit")
	}
}

func TestBuildDatagramConduit_EmptyStack(t *testing.T) {
	// Empty stack should default to UDP
	conduit, err := BuildDatagramConduit("localhost:5683", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if conduit == nil {
		t.Fatal("expected non-nil conduit")
	}
}

func TestBuildDatagramConduit_UnknownLayer(t *testing.T) {
	stack := []domain.LayerHint{{Name: "unknown-protocol"}}

	_, err := BuildDatagramConduit("localhost:5683", stack)
	if err == nil {
		t.Fatal("expected error for unknown layer")
	}
}

func TestBuildFrameConduit(t *testing.T) {
	// Use a test interface name - this won't actually work but tests the builder
	conduit := BuildFrameConduit("lo", nil, 0x88A4)

	if conduit == nil {
		t.Fatal("expected non-nil conduit")
	}
}

func TestBuildEtherCATConduit(t *testing.T) {
	conduit := BuildEtherCATConduit("lo")

	if conduit == nil {
		t.Fatal("expected non-nil conduit")
	}
}

func TestBuildStreamConduit_CaseInsensitive(t *testing.T) {
	tests := []struct {
		name  string
		stack []domain.LayerHint
	}{
		{"lowercase tcp", []domain.LayerHint{{Name: "tcp"}}},
		{"uppercase TCP", []domain.LayerHint{{Name: "TCP"}}},
		{"mixed case Tcp", []domain.LayerHint{{Name: "Tcp"}}},
		{"lowercase tls", []domain.LayerHint{{Name: "tcp"}, {Name: "tls"}}},
		{"uppercase TLS", []domain.LayerHint{{Name: "tcp"}, {Name: "TLS"}}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			conduit, err := BuildStreamConduit("localhost:1883", tc.stack)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if conduit == nil {
				t.Fatal("expected non-nil conduit")
			}
		})
	}
}

func TestBuildDatagramConduit_CaseInsensitive(t *testing.T) {
	tests := []struct {
		name  string
		stack []domain.LayerHint
	}{
		{"lowercase udp", []domain.LayerHint{{Name: "udp"}}},
		{"uppercase UDP", []domain.LayerHint{{Name: "UDP"}}},
		{"lowercase dtls", []domain.LayerHint{{Name: "udp"}, {Name: "dtls"}}},
		{"uppercase DTLS", []domain.LayerHint{{Name: "udp"}, {Name: "DTLS"}}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			conduit, err := BuildDatagramConduit("localhost:5683", tc.stack)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if conduit == nil {
				t.Fatal("expected non-nil conduit")
			}
		})
	}
}

func TestAcquireConnSlot_NilSem(t *testing.T) {
	err := AcquireConnSlot(context.Background(), nil)
	if err != nil {
		t.Fatalf("expected nil error for nil sem, got %v", err)
	}
}

func TestAcquireConnSlot_Acquires(t *testing.T) {
	sem := make(chan struct{}, 2)
	if err := AcquireConnSlot(context.Background(), sem); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sem) != 1 {
		t.Errorf("expected sem len 1, got %d", len(sem))
	}
}

func TestAcquireConnSlot_BlocksWhenFull(t *testing.T) {
	sem := make(chan struct{}, 1)
	sem <- struct{}{} // fill it

	done := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		done <- AcquireConnSlot(ctx, sem)
	}()

	// Should block, then timeout
	err := <-done
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected DeadlineExceeded, got %v", err)
	}

	// Now release and try again — should succeed
	<-sem
	if err := AcquireConnSlot(context.Background(), sem); err != nil {
		t.Fatalf("unexpected error after release: %v", err)
	}
}

func TestAcquireConnSlot_ContextCancelled(t *testing.T) {
	sem := make(chan struct{}, 1)
	sem <- struct{}{} // fill it

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := AcquireConnSlot(ctx, sem)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func TestReleaseConnSlot_NilSem(t *testing.T) {
	// Should not panic
	ReleaseConnSlot(nil)
}

func TestReleaseConnSlot_Releases(t *testing.T) {
	sem := make(chan struct{}, 2)
	sem <- struct{}{}
	sem <- struct{}{}

	ReleaseConnSlot(sem)
	if len(sem) != 1 {
		t.Errorf("expected sem len 1 after release, got %d", len(sem))
	}
}

func TestDialOptionsFromDefaults_CopiesConnSem(t *testing.T) {
	sem := make(chan struct{}, 3)
	defaults := &domain.ConnectionDefaults{
		MaxConnectionsPerTarget: 3,
		ConnSem:                 sem,
	}

	opts := DialOptionsFromDefaults(defaults)
	if opts.ConnSem != sem {
		t.Fatal("expected ConnSem to be propagated from defaults")
	}
}
