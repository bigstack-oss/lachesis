package scenarios

import (
	"time"

	"github.com/bigstack-oss/lachesis/internal/scenariotest"
	"github.com/bigstack-oss/lachesis/internal/scenariotest/steps"
	"github.com/bigstack-oss/lachesis/internal/testenv/scenario"
)

// agentColdRestart is the live regression for the counters-reset epoch
// (lachesis#230/#234, docs/architecture/boot-and-recovery.md#counters-reset-epoch):
// lachesis_agent_counters_reset_timestamp_seconds must carry across a
// warm restart and stamp a fresh value on any empty-WAL boot. It walks
// all three restart shapes on one agent:
//
//  1. WARM (WAL intact) — the epoch carries unchanged and the series
//     stay monotone: the gauge names the last TRUE restart, however
//     many clean restarts happen after it.
//  2. ADOPTED (WAL destroyed, pinned maps alive — agent reinstall /
//     WAL-volume loss) — a fresh epoch stamps, and the series stay
//     monotone anyway: the kernel counters carry the history, the
//     rebuilt state re-seeds from them, nothing is lost. The stamped
//     epoch is the "spurious split is billing-free" half of the ETL
//     contract's baseline-subtraction design.
//  3. ZERO (WAL and pins destroyed — the host-reboot shape) — a fresh
//     epoch stamps again, the series legitimately restart from zero,
//     and new traffic accrues on the fresh counters. The declared
//     epoch is what lets the ETL split the day instead of clamping it.
//
// Sibling of wal-restart-continuity (#185), which pins the warm path's
// billing continuity in detail. SKIPs when agent_control (or its
// wal_path/pin_path) is unconfigured — environment, not defect.
func agentColdRestart() *scenariotest.Scenario {
	b := scenario.New()
	b.Network("net-T1", "T1").
		Subnet("sub-T1", "10.0.34.0/24", "10.0.34.1").
		VM("vm-a", "T1", "10.0.34.5").
		VM("vm-b", "T1", "10.0.34.6")
	b.ExternalNetwork("net-ext", "admin")
	b.Router("r-T1", "T1").
		Attach("sub-T1", "10.0.34.1").
		ExternalGateway("net-ext")

	// The agent's first post-restart drain runs one scrape interval
	// after boot; series read empty until it lands. The warm leg is
	// immune (the WAL restore pre-fills state), the two cold legs are
	// not — they wait one interval before asserting.
	const drainWait = 15 * time.Second

	return &scenariotest.Scenario{
		Name:    "agent-cold-restart",
		Desc:    "Warm restart carries the counters-reset epoch; WAL loss (pins adopted) and WAL+pin loss (zero restart) each stamp a fresh one (lachesis#230/#234, step-scripted).",
		Builder: b,
		// Both VMs ride the restarted agent's node: the scenario reads
		// one agent's own taps across its restarts.
		Placement: scenariotest.Placement{
			"vm-a": "node:0",
			"vm-b": "node:0",
		},
		Steps: []scenariotest.Step{
			steps.DriveStep{Flows: []scenariotest.Flow{
				{From: "vm-a", To: scenariotest.VMTarget("vm-b"), Bytes: 1 << 20, Proto: scenariotest.TCP},
			}},
			steps.AssertStep{Note: "baseline drive", Expect: []scenariotest.Expect{
				{TenantID: "T1", Zone: "same_tenant", Direction: "tx", MinBytes: 1 << 20},
			}},

			// Leg 1 — WARM: WAL intact, epoch carries, series monotone.
			steps.CaptureStep{},
			steps.RestartAgentStep{},
			steps.EpochStep{Changed: false,
				Note: "warm restart carries the stored epoch"},
			steps.MonotoneStep{Tenant: "T1", Note: "series monotone across the warm restart"},

			// Leg 2 — ADOPTED: WAL destroyed, pins alive. Fresh epoch,
			// and the live kernel counters carry on — new traffic keeps
			// accruing on the surviving cumulative (the shape where the
			// old zero-based ETL math would have double-billed, and the
			// reason the epoch means "baselines not comparable", not
			// "at zero"). Deliberately NOT a monotone assertion: the
			// settled accumulators live only in the WAL, so any prior
			// churn's folded bytes drop out of the exposed series here —
			// that drop aligns with the declared epoch and is exactly
			// what the ETL's per-segment baseline subtraction absorbs
			// (docs/architecture/billing.md, "Declared discontinuities").
			steps.CaptureStep{},
			steps.RestartAgentStep{RemoveWAL: true},
			steps.EpochStep{Changed: true,
				Note: "WAL loss stamps a fresh epoch (adopted pins)"},
			steps.SleepStep{Duration: drainWait},
			steps.DriveStep{Flows: []scenariotest.Flow{
				{From: "vm-a", To: scenariotest.VMTarget("vm-b"), Bytes: 1 << 20, Proto: scenariotest.TCP},
			}},
			steps.AssertStep{Note: "adopted counters keep counting after WAL loss", Expect: []scenariotest.Expect{
				{TenantID: "T1", Zone: "same_tenant", Direction: "tx", MinBytes: 1 << 20},
			}},

			// Leg 3 — ZERO: WAL and pins destroyed (host-reboot shape).
			// Fresh epoch again; series legitimately restart, and new
			// traffic accrues on the fresh counters.
			steps.CaptureStep{},
			steps.RestartAgentStep{RemoveWAL: true, RemovePins: true},
			steps.EpochStep{Changed: true,
				Note: "WAL+pin loss stamps a fresh epoch (zero restart)"},
			steps.SleepStep{Duration: drainWait},
			steps.DriveStep{Flows: []scenariotest.Flow{
				{From: "vm-a", To: scenariotest.VMTarget("vm-b"), Bytes: 1 << 20, Proto: scenariotest.TCP},
			}},
			// Tenant-level only: right after a zero restart the server
			// family legitimately has no series until the first drain,
			// which the assert's build-vintage guard (family absent =
			// pre-per-server agent?) would misread as a config error.
			steps.AssertStep{Note: "fresh counters accrue after the zero restart", Expect: []scenariotest.Expect{
				{TenantID: "T1", Zone: "same_tenant", Direction: "tx", MinBytes: 1 << 20},
			}},
		},
	}
}
