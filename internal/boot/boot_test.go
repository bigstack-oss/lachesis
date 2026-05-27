package boot

import (
	"strings"
	"sync"
	"testing"
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
