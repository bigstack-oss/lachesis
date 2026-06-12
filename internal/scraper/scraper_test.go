package scraper_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/bpf"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/scraper"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/state"
)

// fakeReader is the unit-test MapReader. It returns whatever its
// returns slice contains on each call, indexed by callCount, and can
// be told to error on a given call.
type fakeReader struct {
	calls   atomic.Uint64
	returns []map[bpf.FlowKey]bpf.FlowMetrics
	errOn   int // 0 = never; 1 = first call; etc.
}

func (f *fakeReader) BatchLookup(dst map[bpf.FlowKey]bpf.FlowMetrics) error {
	call := f.calls.Add(1)
	if f.errOn != 0 && int(call) == f.errOn {
		return errors.New("synthetic reader failure")
	}
	idx := int(call) - 1
	if idx >= len(f.returns) {
		idx = len(f.returns) - 1
	}
	for k, v := range f.returns[idx] {
		dst[k] = v
	}
	return nil
}

func key(srcLast, dstLast byte) bpf.FlowKey {
	return bpf.FlowKey{
		SrcMac:    [6]uint8{0xaa, 0, 0, 0, 0, srcLast},
		DstMac:    [6]uint8{0xaa, 0, 0, 0, 0, dstLast},
		EthProto:  0x0800,
		Direction: bpf.DirectionEgress,
		DstZone:   bpf.ZoneExternal,
	}
}

func TestTick_AppliesDeltasForEachEntry(t *testing.T) {
	r := &fakeReader{
		returns: []map[bpf.FlowKey]bpf.FlowMetrics{
			{
				key(1, 2): {Bytes: 100, Packets: 2, LastSeenNs: 10},
				key(3, 4): {Bytes: 200, Packets: 5, LastSeenNs: 11},
			},
			{
				key(1, 2): {Bytes: 350, Packets: 8, LastSeenNs: 20}, // +250/+6
				key(3, 4): {Bytes: 200, Packets: 5, LastSeenNs: 11}, // unchanged
			},
		},
	}
	st := state.New()
	s := scraper.New(r, st, time.Second)

	if err := s.Tick(); err != nil {
		t.Fatalf("Tick 1: %v", err)
	}
	if err := s.Tick(); err != nil {
		t.Fatalf("Tick 2: %v", err)
	}

	want := map[bpf.FlowKey]bpf.FlowMetrics{
		key(1, 2): {Bytes: 350, Packets: 8, LastSeenNs: 20},
		key(3, 4): {Bytes: 200, Packets: 5, LastSeenNs: 11},
	}
	got := map[bpf.FlowKey]bpf.FlowMetrics{}
	for _, e := range st.Snapshot(nil) {
		got[e.Key] = e.Total
	}
	if len(got) != len(want) {
		t.Fatalf("len(state) = %d, want %d", len(got), len(want))
	}
	for k, w := range want {
		if got[k] != w {
			t.Errorf("Total[%v] = %+v, want %+v", k, got[k], w)
		}
	}
}

func TestTick_ClearsBufferBetweenTicks(t *testing.T) {
	// First tick reports two flows; second tick reports only one. The
	// other must NOT be re-applied on tick 2 (would be a phantom delta).
	r := &fakeReader{
		returns: []map[bpf.FlowKey]bpf.FlowMetrics{
			{
				key(1, 2): {Bytes: 100, Packets: 1, LastSeenNs: 5},
				key(3, 4): {Bytes: 200, Packets: 2, LastSeenNs: 5},
			},
			{
				key(1, 2): {Bytes: 150, Packets: 2, LastSeenNs: 10},
			},
		},
	}
	st := state.New()
	s := scraper.New(r, st, time.Second)

	if err := s.Tick(); err != nil {
		t.Fatalf("Tick 1: %v", err)
	}
	if err := s.Tick(); err != nil {
		t.Fatalf("Tick 2: %v", err)
	}

	got := map[bpf.FlowKey]bpf.FlowMetrics{}
	for _, e := range st.Snapshot(nil) {
		got[e.Key] = e.Total
	}
	// key(3,4) was only seen on tick 1; Total should stay at 200/2/5
	// even though it was absent from tick 2's reading.
	if got[key(3, 4)].Bytes != 200 {
		t.Errorf("key(3,4) Total.Bytes = %d, want 200 (absence ≠ delta)", got[key(3, 4)].Bytes)
	}
	if got[key(1, 2)].Bytes != 150 {
		t.Errorf("key(1,2) Total.Bytes = %d, want 150", got[key(1, 2)].Bytes)
	}
}

func TestTick_ErrorIncrementsCounterAndLeavesStateUntouched(t *testing.T) {
	r := &fakeReader{
		returns: []map[bpf.FlowKey]bpf.FlowMetrics{nil},
		errOn:   1,
	}
	st := state.New()
	s := scraper.New(r, st, time.Second)

	if err := s.Tick(); err == nil {
		t.Fatal("Tick: expected error, got nil")
	}
	if got := s.ErrorCount(); got != 1 {
		t.Errorf("ErrorCount = %d, want 1", got)
	}
	if got := s.LastSuccessUnix(); got != 0 {
		t.Errorf("LastSuccessUnix = %d, want 0 (no successful tick yet)", got)
	}
	if got := st.Len(); got != 0 {
		t.Errorf("state.Len = %d, want 0", got)
	}
}

func TestTick_LastSuccessUnixUpdated(t *testing.T) {
	r := &fakeReader{returns: []map[bpf.FlowKey]bpf.FlowMetrics{{}}}
	s := scraper.New(r, state.New(), time.Second)

	before := time.Now().Unix()
	if err := s.Tick(); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	after := time.Now().Unix()

	got := s.LastSuccessUnix()
	if got < before || got > after {
		t.Errorf("LastSuccessUnix = %d, want in [%d, %d]", got, before, after)
	}
}

func TestRun_RespectsContextCancel(t *testing.T) {
	r := &fakeReader{returns: []map[bpf.FlowKey]bpf.FlowMetrics{{}}}
	s := scraper.New(r, state.New(), 10*time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		s.Run(ctx)
		close(done)
	}()

	// Let a few ticks fire, then cancel.
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run did not return within 1s of cancel")
	}
	if got := r.calls.Load(); got < 2 {
		t.Errorf("reader.calls = %d, want ≥2 (at least one initial + one ticker)", got)
	}
}

// TestRun_FinalTickOnCancel proves the shutdown drain: after ctx is
// cancelled, Run performs one final Tick before returning, so deltas
// applied to the kernel map since the last periodic tick still reach
// GlobalState. Without it, a graceful shutdown loses up to one scrape
// interval of billing data.
func TestRun_FinalTickOnCancel(t *testing.T) {
	r := &fakeReader{
		returns: []map[bpf.FlowKey]bpf.FlowMetrics{
			{key(1, 2): {Bytes: 100, Packets: 1, LastSeenNs: 5}},
			{key(1, 2): {Bytes: 250, Packets: 4, LastSeenNs: 9}}, // only the final tick can see this
		},
	}
	st := state.New()
	s := scraper.New(r, st, time.Hour) // ticker never fires; initial + final ticks only

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		s.Run(ctx)
		close(done)
	}()

	// Wait for the initial tick to start (and, with it in flight or
	// done, cancel — Run must still run exactly one more tick).
	deadline := time.Now().Add(time.Second)
	for r.calls.Load() < 1 {
		if time.Now().After(deadline) {
			t.Fatal("initial tick did not fire within 1s")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run did not return within 1s of cancel")
	}

	if got := r.calls.Load(); got != 2 {
		t.Errorf("reader.calls = %d, want 2 (initial + final)", got)
	}
	got := map[bpf.FlowKey]bpf.FlowMetrics{}
	for _, e := range st.Snapshot(nil) {
		got[e.Key] = e.Total
	}
	if want := (bpf.FlowMetrics{Bytes: 250, Packets: 4, LastSeenNs: 9}); got[key(1, 2)] != want {
		t.Errorf("Total[key(1,2)] = %+v, want %+v (final tick not integrated)", got[key(1, 2)], want)
	}
}

func TestRun_SurvivesReaderErrors(t *testing.T) {
	r := &fakeReader{
		returns: []map[bpf.FlowKey]bpf.FlowMetrics{
			{}, // tick 1 success
			{}, // tick 2 - will be errored
			{key(1, 2): {Bytes: 1, Packets: 1, LastSeenNs: 1}},
		},
		errOn: 2,
	}
	s := scraper.New(r, state.New(), 5*time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)

	// Wait long enough for at least 3 ticks (~15ms; plus initial = 4).
	time.Sleep(60 * time.Millisecond)

	if got := s.ErrorCount(); got < 1 {
		t.Errorf("ErrorCount = %d, want ≥1", got)
	}
	if got := r.calls.Load(); got < 3 {
		t.Errorf("reader.calls = %d, want ≥3 (loop survived the error)", got)
	}
}
