// stats.go reads the kernel `telemetry_stats` PERCPU_ARRAY — the
// failure/skip counters bpf/telemetry.c increments when a
// telemetry_map insert is rejected or a non-IP frame is passed
// through uncounted. The slot vocabulary ([StatReason], [StatCounts])
// lives in schema.go; the Prometheus export lives in metrics.go.

package bpf

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
)

// StatsReader sums the per-CPU `telemetry_stats` slots into one
// cumulative [StatCounts]. The agent's scrape loop calls [StatsReader.Read]
// once per drain — the kernel values are monotonic, so each read is a
// complete snapshot, never a delta.
type StatsReader struct {
	m *ebpf.Map
	// buf receives the per-CPU values of one slot; reused across
	// reads so steady-state Read does not grow a fresh slice.
	buf []uint64
}

// NewStatsReader wraps an [*ebpf.Map] (telemetry_stats). The map must
// be the PERCPU_ARRAY declared in bpf/telemetry.c; constructor errors
// on nil.
func NewStatsReader(m *ebpf.Map) (*StatsReader, error) {
	if m == nil {
		return nil, errors.New("bpf: NewStatsReader: map is nil")
	}
	return &StatsReader{m: m}, nil
}

// Read looks up every [StatReason] slot and sums it across CPUs.
// Returns the zero [StatCounts] alongside the error if any lookup
// fails, so a partial read never masquerades as a counter reset.
func (r *StatsReader) Read() (StatCounts, error) {
	var counts StatCounts
	for reason := StatReason(0); reason < statReasonCount; reason++ {
		slot := uint32(reason)
		if err := r.m.Lookup(&slot, &r.buf); err != nil {
			return StatCounts{}, fmt.Errorf("bpf: lookup %s[%s]: %w", MapTelemetryStats, reason, err)
		}
		var sum uint64
		for _, v := range r.buf {
			sum += v
		}
		counts[reason] = sum
	}
	return counts, nil
}
