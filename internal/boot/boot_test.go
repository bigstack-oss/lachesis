package boot

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestPhaseString(t *testing.T) {
	cases := []struct {
		p    Phase
		want string
	}{
		{PhaseInit, "init"},
		{PhaseBPFLoaded, "bpf_loaded"},
		{PhaseMetadataReady, "metadata_ready"},
		{PhaseAttached, "attached"},
		{PhaseStateRestored, "state_restored"},
		{Phase(99), "phase(99)"},
	}
	for _, c := range cases {
		if got := c.p.String(); got != c.want {
			t.Errorf("Phase(%d).String() = %q, want %q", int(c.p), got, c.want)
		}
	}
}

func TestSequencer_HappyPath(t *testing.T) {
	s := New()
	if got := s.Current(); got != PhaseInit {
		t.Fatalf("new sequencer: Current() = %s, want %s", got, PhaseInit)
	}
	phases := []Phase{PhaseBPFLoaded, PhaseMetadataReady, PhaseAttached, PhaseStateRestored}
	for _, p := range phases {
		if err := s.Advance(p); err != nil {
			t.Fatalf("Advance(%s): %v", p, err)
		}
		if got := s.Current(); got != p {
			t.Errorf("after Advance(%s): Current() = %s, want %s", p, got, p)
		}
	}
}

func TestSequencer_RejectsBadTransitions(t *testing.T) {
	cases := []struct {
		name    string
		setup   []Phase
		bad     Phase
		wantMsg string
	}{
		{
			name:    "skip from init",
			setup:   nil,
			bad:     PhaseMetadataReady,
			wantMsg: "cannot advance from init to metadata_ready",
		},
		{
			name:    "skip mid-sequence",
			setup:   []Phase{PhaseBPFLoaded},
			bad:     PhaseAttached,
			wantMsg: "cannot advance from bpf_loaded to attached",
		},
		{
			name:    "rewind",
			setup:   []Phase{PhaseBPFLoaded, PhaseMetadataReady},
			bad:     PhaseBPFLoaded,
			wantMsg: "cannot advance from metadata_ready to bpf_loaded",
		},
		{
			name:    "re-advance to same phase",
			setup:   []Phase{PhaseBPFLoaded},
			bad:     PhaseBPFLoaded,
			wantMsg: "cannot advance from bpf_loaded to bpf_loaded",
		},
		{
			name:    "advance to init",
			setup:   []Phase{PhaseBPFLoaded},
			bad:     PhaseInit,
			wantMsg: "cannot advance from bpf_loaded to init",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := New()
			for _, p := range c.setup {
				if err := s.Advance(p); err != nil {
					t.Fatalf("setup Advance(%s): %v", p, err)
				}
			}
			err := s.Advance(c.bad)
			if err == nil {
				t.Fatalf("Advance(%s) returned nil, want error", c.bad)
			}
			if !strings.Contains(err.Error(), c.wantMsg) {
				t.Errorf("Advance(%s) error = %q, want substring %q", c.bad, err, c.wantMsg)
			}
			last := PhaseInit
			if n := len(c.setup); n > 0 {
				last = c.setup[n-1]
			}
			if got := s.Current(); got != last {
				t.Errorf("after rejected Advance: Current() = %s, want %s (unchanged)", got, last)
			}
		})
	}
}

func TestSequencer_AwaitAlreadyReached(t *testing.T) {
	s := New()
	for _, p := range []Phase{PhaseBPFLoaded, PhaseMetadataReady} {
		if err := s.Advance(p); err != nil {
			t.Fatalf("Advance(%s): %v", p, err)
		}
	}
	// Awaiting a phase that has already passed must return immediately.
	if err := s.Await(context.Background(), PhaseBPFLoaded); err != nil {
		t.Errorf("Await(already-reached) = %v, want nil", err)
	}
	if err := s.Await(context.Background(), PhaseInit); err != nil {
		t.Errorf("Await(init) = %v, want nil", err)
	}
}

func TestSequencer_AwaitReleasedByAdvance(t *testing.T) {
	s := New()
	got := make(chan error, 1)
	go func() { got <- s.Await(context.Background(), PhaseStateRestored) }()

	// The awaiter must still be blocked before the phase is reached.
	if err := s.Advance(PhaseBPFLoaded); err != nil {
		t.Fatalf("Advance: %v", err)
	}
	select {
	case err := <-got:
		t.Fatalf("Await returned early with %v, want still blocked at PhaseBPFLoaded", err)
	case <-time.After(20 * time.Millisecond):
	}

	for _, p := range []Phase{PhaseMetadataReady, PhaseAttached, PhaseStateRestored} {
		if err := s.Advance(p); err != nil {
			t.Fatalf("Advance(%s): %v", p, err)
		}
	}
	select {
	case err := <-got:
		if err != nil {
			t.Errorf("Await = %v, want nil once phase reached", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Await did not return after its phase was reached")
	}
}

func TestSequencer_AwaitCtxCancel(t *testing.T) {
	s := New()
	ctx, cancel := context.WithCancel(context.Background())
	got := make(chan error, 1)
	go func() { got <- s.Await(ctx, PhaseStateRestored) }()
	cancel()
	select {
	case err := <-got:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("Await after cancel = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Await did not return after ctx cancel")
	}
}

func TestSequencer_FailReleasesAwaiters(t *testing.T) {
	s := New()
	const n = 4
	got := make(chan error, n)
	for i := 0; i < n; i++ {
		go func() { got <- s.Await(context.Background(), PhaseStateRestored) }()
	}
	sentinel := errors.New("neutron unreachable")
	s.Fail(PhaseMetadataReady, sentinel)
	for i := 0; i < n; i++ {
		select {
		case err := <-got:
			if !errors.Is(err, sentinel) {
				t.Errorf("Await after Fail = %v, want wrapping %v", err, sentinel)
			}
			if !strings.Contains(err.Error(), "metadata_ready") {
				t.Errorf("Await error = %q, want it to name the failing phase", err)
			}
		case <-time.After(time.Second):
			t.Fatal("Await did not return after Fail")
		}
	}
}

func TestSequencer_FailFirstWins(t *testing.T) {
	s := New()
	first := errors.New("first")
	s.Fail(PhaseBPFLoaded, first)
	s.Fail(PhaseAttached, errors.New("second"))
	err := s.Await(context.Background(), PhaseStateRestored)
	if !errors.Is(err, first) {
		t.Errorf("Await = %v, want the first Fail (%v)", err, first)
	}
}

func TestSequencer_ReachedBeatsLaterFail(t *testing.T) {
	s := New()
	if err := s.Advance(PhaseBPFLoaded); err != nil {
		t.Fatalf("Advance: %v", err)
	}
	s.Fail(PhaseMetadataReady, errors.New("aborted after bpf_loaded"))
	// PhaseBPFLoaded was reached before the failure, so its guarantee
	// holds: Await must report success, not the later abort.
	if err := s.Await(context.Background(), PhaseBPFLoaded); err != nil {
		t.Errorf("Await(reached-before-fail) = %v, want nil", err)
	}
}

func TestSequencer_AwaitInvalidPhase(t *testing.T) {
	s := New()
	if err := s.Await(context.Background(), Phase(99)); err == nil {
		t.Error("Await(invalid) = nil, want error")
	}
}

func TestSequencer_ConcurrentCurrent(t *testing.T) {
	s := New()
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_ = s.Current()
				}
			}
		}()
	}
	for _, p := range []Phase{PhaseBPFLoaded, PhaseMetadataReady, PhaseAttached, PhaseStateRestored} {
		if err := s.Advance(p); err != nil {
			t.Fatalf("Advance(%s): %v", p, err)
		}
	}
	close(stop)
	wg.Wait()
	if got := s.Current(); got != PhaseStateRestored {
		t.Errorf("final Current() = %s, want %s", got, PhaseStateRestored)
	}
}
