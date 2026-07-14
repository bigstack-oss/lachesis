//go:build linux

package agent

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"

	"github.com/bigstack-oss/lachesis/internal/bpf"
)

// batchSize is the maximum number of keys requested per BPF_MAP_LOOKUP_BATCH
// syscall. 256 is a moderate value: large enough to amortise syscall cost
// across the typical compute-host flow count, small enough that the
// keysBuf + valsBuf allocation per Reader stays under one OS page.
const batchSize = 256

// BPFMapReader implements [scraper.MapReader] over a kernel
// PERCPU_HASH map (telemetry_map). The buffers are allocated once
// at construction and reused across ticks; BatchLookup itself is
// allocation-free in steady state.
type BPFMapReader struct {
	m       *ebpf.Map
	numCPU  int
	keysBuf []bpf.FlowKey
	// valsBuf is a flat per-CPU-major slice of length batchSize*numCPU.
	// Entry i covers keysBuf[i] across CPUs in valsBuf[i*numCPU : (i+1)*numCPU].
	valsBuf []bpf.FlowMetrics
}

// NewBPFMapReader wraps an [*ebpf.Map] (telemetry_map). The map must
// be a PERCPU_HASH with key type [bpf.FlowKey] and value type
// [bpf.FlowMetrics]; constructor errors otherwise.
func NewBPFMapReader(m *ebpf.Map) (*BPFMapReader, error) {
	if m == nil {
		return nil, errors.New("agent: NewBPFMapReader: map is nil")
	}
	n, err := ebpf.PossibleCPU()
	if err != nil {
		return nil, fmt.Errorf("agent: query possible CPUs: %w", err)
	}
	return &BPFMapReader{
		m:       m,
		numCPU:  n,
		keysBuf: make([]bpf.FlowKey, batchSize),
		valsBuf: make([]bpf.FlowMetrics, batchSize*n),
	}, nil
}

// BatchLookup drains the kernel map in chunks of up to [batchSize]
// keys per syscall, aggregating per-CPU values into a single
// [bpf.FlowMetrics] per key and writing the result into dst.
//
// Caller is responsible for clearing dst before invocation; the
// [scraper] does this.
func (r *BPFMapReader) BatchLookup(dst map[bpf.FlowKey]bpf.FlowMetrics) error {
	var cursor ebpf.MapBatchCursor
	for {
		n, err := r.m.BatchLookup(&cursor, r.keysBuf, r.valsBuf, nil)
		for i := 0; i < n; i++ {
			var sum bpf.FlowMetrics
			base := i * r.numCPU
			for j := 0; j < r.numCPU; j++ {
				v := r.valsBuf[base+j]
				sum.Bytes += v.Bytes
				sum.Packets += v.Packets
				if v.LastSeenNs > sum.LastSeenNs {
					sum.LastSeenNs = v.LastSeenNs
				}
			}
			dst[r.keysBuf[i]] = sum
		}
		// ErrKeyNotExist signals "last batch"; both partial-with-error
		// and clean-end-of-map flow through here.
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("agent: batch lookup: %w", err)
		}
		// err == nil means there may be more entries; loop.
	}
}
