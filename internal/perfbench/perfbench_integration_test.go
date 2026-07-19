//go:build integration

package perfbench_test

import (
	"testing"

	"github.com/bigstack-oss/lachesis/internal/bpf"
	"github.com/bigstack-oss/lachesis/internal/perfbench"
)

// perPacketCeilingNs is the absolute upper bound, in nanoseconds, on the
// telemetry classifier's per-packet cost measured via BPF_PROG_TEST_RUN.
//
// Zero means uncalibrated: the gate records the measured cost and does not
// fail, so the first CI run on the shared runner establishes a baseline
// without reddening the build. Arm the gate by setting this to ~2–3× that
// baseline — a generous bound that catches a doubling or tripling from a new
// map lookup or classification branch in bpf/telemetry.c, deliberately not a
// 10% drift detector. See docs/test-strategy.md.
var perPacketCeilingNs int64

// TestPerfbench_PerPacketCeiling fails the build when the classifier's
// per-packet cost exceeds perPacketCeilingNs. It rides the integration job
// (privileged Docker) because BPF_PROG_TEST_RUN is a kernel syscall.
func TestPerfbench_PerPacketCeiling(t *testing.T) {
	r, err := perfbench.Run(perfbench.Config{
		Repeat:  1_000_000,
		Program: bpf.ProgramIngress,
	})
	if err != nil {
		t.Fatalf("perfbench run: %v", err)
	}

	t.Logf("telemetry classifier %s: %d ns/packet over %d repeats",
		r.Program, r.PerRunNs, r.Repeat)

	if perPacketCeilingNs <= 0 {
		t.Skip("per-packet ceiling uncalibrated — recording baseline only")
	}
	if r.PerRunNs > perPacketCeilingNs {
		t.Fatalf("per-packet cost %d ns exceeds ceiling %d ns — a bpf/telemetry.c change inflated the hot path",
			r.PerRunNs, perPacketCeilingNs)
	}
}
