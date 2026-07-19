// Package bpfunit drives BPF programs through BPF_PROG_TEST_RUN for unit
// testing and microbenchmarking.
//
// It wraps the cilium/ebpf primitives with a small surface so test authors
// don't deal with CollectionSpec lifecycles or syscall semantics directly.
// Production code does not import this package.
package bpfunit

import (
	"fmt"
	"time"

	"github.com/cilium/ebpf"
)

// Driver owns a loaded BPF Collection and exposes Run / RunRepeat for tests.
//
// The zero value is not usable; call New.
type Driver struct {
	coll *ebpf.Collection
}

// New loads spec into the kernel and returns a Driver. The caller owns the
// returned Driver and must Close it.
func New(spec *ebpf.CollectionSpec) (*Driver, error) {
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("bpfunit: load collection: %w", err)
	}
	return &Driver{coll: coll}, nil
}

// Run executes progName against frame and returns the BPF verdict.
//
// frame must be a complete L2 Ethernet frame — use the builders in packet.go.
// The verdict is the program's return value (TC_ACT_OK=0, TC_ACT_SHOT=2, …).
func (d *Driver) Run(progName string, frame []byte) (verdict uint32, err error) {
	prog, ok := d.coll.Programs[progName]
	if !ok {
		return 0, fmt.Errorf("bpfunit: program %q not in collection", progName)
	}
	ret, _, err := prog.Test(frame)
	if err != nil {
		return 0, fmt.Errorf("bpfunit: prog %q test run: %w", progName, err)
	}
	return ret, nil
}

// RunRepeat executes progName count times in a single syscall and reports
// per-run kernel-measured runtime plus the extrapolated total.
//
// The kernel times only program execution (excludes the syscall boundary),
// making this the right primitive for ns/packet benchmarks. cilium/ebpf's
// Benchmark already returns the time *per iteration* (the kernel averages
// over count internally), so perRun is that value directly — do not divide
// by count again — and total is perRun reconstructed across the run.
func (d *Driver) RunRepeat(progName string, frame []byte, count uint32) (total, perRun time.Duration, err error) {
	if count == 0 {
		return 0, 0, fmt.Errorf("bpfunit: count must be > 0")
	}
	prog, ok := d.coll.Programs[progName]
	if !ok {
		return 0, 0, fmt.Errorf("bpfunit: program %q not in collection", progName)
	}
	_, perRun, err = prog.Benchmark(frame, int(count), nil)
	if err != nil {
		return 0, 0, fmt.Errorf("bpfunit: prog %q benchmark: %w", progName, err)
	}
	return perRun * time.Duration(count), perRun, nil
}

// Map returns the named BPF map, or nil if not loaded.
func (d *Driver) Map(name string) *ebpf.Map {
	return d.coll.Maps[name]
}

// Program returns the named BPF program, or nil if not loaded.
// Tests that attach the program to a real interface via TC need the *ebpf.Program;
// tests that exercise it via BPF_PROG_TEST_RUN should use Run / RunRepeat.
func (d *Driver) Program(name string) *ebpf.Program {
	return d.coll.Programs[name]
}

// Close releases the BPF resources held by the driver. Safe to call twice.
func (d *Driver) Close() error {
	if d.coll == nil {
		return nil
	}
	d.coll.Close()
	d.coll = nil
	return nil
}
