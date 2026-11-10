package drive

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bigstack-oss/lachesis/internal/scenariotest"
	"github.com/bigstack-oss/lachesis/internal/scenariotest/fake"
)

// streamGate is a VM exec whose stream command blocks until released
// or cancelled, so a test can act while the flow is in flight.
type streamGate struct {
	entered    chan struct{}
	release    chan struct{}
	failStream bool

	mu       sync.Mutex
	finished bool
}

func newStreamGate() *streamGate {
	return &streamGate{entered: make(chan struct{}), release: make(chan struct{})}
}

func (g *streamGate) Run(ctx context.Context, _, command string) (string, error) {
	if !strings.Contains(command, "| nc ") {
		return "", nil
	}
	close(g.entered)
	select {
	case <-g.release:
	case <-ctx.Done():
		return "", ctx.Err()
	}
	g.mu.Lock()
	g.finished = true
	g.mu.Unlock()
	if g.failStream {
		return "", errors.New("stream broke")
	}
	return "", nil
}

func (g *streamGate) isFinished() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.finished
}

// awaitStream blocks until the stream command has started.
func (g *streamGate) awaitStream(t *testing.T) {
	t.Helper()
	select {
	case <-g.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("stream never started")
	}
}

// awaitFinished blocks until the stream command has returned normally.
func (g *streamGate) awaitFinished(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !g.isFinished() {
		if time.Now().After(deadline) {
			t.Fatal("stream never finished")
		}
		time.Sleep(time.Millisecond)
	}
}

func duringOpts(t *testing.T, exec scenariotest.VMExec, during func(context.Context) error) Options {
	t.Helper()
	sc := fake.SameTenantScenario()
	sc.Flows = []scenariotest.Flow{{From: "vm-a", To: scenariotest.VMTarget("vm-b"), Bytes: 1 << 20, Proto: scenariotest.TCP}}
	return Options{
		Config:    fake.Config(),
		Scenario:  sc,
		State:     driveState(),
		StatePath: t.TempDir() + "/state.json",
		Metrics:   fake.HealthyMetrics{Attached: 7},
		Exec:      exec,
		Log:       slog.New(slog.DiscardHandler),
		SinkDelay: -1,
		During:    during,
	}
}

// TestDrive_DuringOverlapsTheStream: During runs while the stream is in
// flight, and Run returns only once both are done, whichever ends last.
func TestDrive_DuringOverlapsTheStream(t *testing.T) {
	for _, streamEndsFirst := range []bool{false, true} {
		g := newStreamGate()
		duringDone := false
		during := func(context.Context) error {
			g.awaitStream(t)
			if g.isFinished() {
				t.Error("During ran after the stream finished")
			}
			close(g.release)
			if streamEndsFirst {
				g.awaitFinished(t)
			}
			duringDone = true
			return nil
		}
		if err := Run(context.Background(), duringOpts(t, g, during)); err != nil {
			t.Fatalf("streamEndsFirst=%v: Drive: %v", streamEndsFirst, err)
		}
		if !duringDone || !g.isFinished() {
			t.Errorf("streamEndsFirst=%v: Run returned with during done=%v, stream done=%v; want both", streamEndsFirst, duringDone, g.isFinished())
		}
	}
}

// TestDrive_DuringErrorCancelsTheStream: a During failure is the
// drive's error, and the still-running stream is cancelled rather than
// waited out.
func TestDrive_DuringErrorCancelsTheStream(t *testing.T) {
	g := newStreamGate()
	during := func(context.Context) error {
		g.awaitStream(t)
		return errors.New("restart failed")
	}
	err := Run(context.Background(), duringOpts(t, g, during))
	if err == nil || !strings.Contains(err.Error(), "restart failed") {
		t.Fatalf("err = %v, want the During failure", err)
	}
	if g.isFinished() {
		t.Error("stream ran to completion; a During failure must cancel it")
	}
}

// TestDrive_FlowErrorWhileDuring: a stream failing mid-During is the
// drive's error, returned after During finishes.
func TestDrive_FlowErrorWhileDuring(t *testing.T) {
	g := newStreamGate()
	g.failStream = true
	duringDone := false
	during := func(context.Context) error {
		g.awaitStream(t)
		close(g.release)
		g.awaitFinished(t)
		duringDone = true
		return nil
	}
	err := Run(context.Background(), duringOpts(t, g, during))
	if err == nil || !strings.Contains(err.Error(), "stream broke") {
		t.Fatalf("err = %v, want the stream failure", err)
	}
	if !duringDone {
		t.Error("Run returned before During finished")
	}
}

// TestDrive_DuringAfterTheFlowsIsAnError: flows that finish before
// During starts overlapped nothing; that must fail, not pass silently.
func TestDrive_DuringAfterTheFlowsIsAnError(t *testing.T) {
	called := false
	opts := duringOpts(t, &fake.Exec{}, func(context.Context) error { called = true; return nil })
	opts.DuringAfter = time.Hour
	err := Run(context.Background(), opts)
	if err == nil || !strings.Contains(err.Error(), "finished before During started") {
		t.Fatalf("err = %v, want the no-overlap error", err)
	}
	if called {
		t.Error("During ran although the flows had already finished")
	}
}

func TestDrive_PacedStream(t *testing.T) {
	exec := &fake.Exec{}
	opts := duringOpts(t, exec, nil)
	opts.Scenario.Flows[0].Bytes = 100 << 20
	opts.PaceMiB = 32
	if err := Run(context.Background(), opts); err != nil {
		t.Fatalf("Drive: %v", err)
	}
	want := "for i in $(seq 4); do dd if=/dev/zero bs=1M count=32 2>/dev/null; sleep 1; done | nc 10.0.1.6 15000"
	for _, c := range exec.Calls {
		if c.Command == want {
			return
		}
	}
	t.Errorf("no paced stream %q in %+v", want, exec.Calls)
}

// TestDrive_PaceOverSSHTimeoutRefused: a paced stream the per-command
// SSH budget would kill mid-flow is refused before any traffic.
func TestDrive_PaceOverSSHTimeoutRefused(t *testing.T) {
	exec := &fake.Exec{}
	opts := duringOpts(t, exec, nil)
	opts.Config.SSH.Timeout = 10 * time.Second
	opts.Scenario.Flows[0].Bytes = 20 << 20
	opts.PaceMiB = 1
	err := Run(context.Background(), opts)
	if err == nil || !strings.Contains(err.Error(), "ssh.timeout") {
		t.Fatalf("err = %v, want the ssh.timeout refusal", err)
	}
	if len(exec.Calls) != 0 {
		t.Errorf("exec ran %d command(s) before the refusal", len(exec.Calls))
	}
}
