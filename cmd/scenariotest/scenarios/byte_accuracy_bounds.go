package scenarios

import (
	"time"

	"github.com/bigstack-oss/lachesis/internal/scenariotest"
	"github.com/bigstack-oss/lachesis/internal/scenariotest/steps"
	"github.com/bigstack-oss/lachesis/internal/testenv/scenario"
)

const (
	// accuracyDriveBytes is the exact payload the drive streams. Large
	// enough that per-connection constants (handshake, ARP, neighbour
	// chatter) vanish into the tolerance.
	accuracyDriveBytes = 8 << 20

	// accuracyUpperBound is the ceiling on what the tap may count for
	// the drive, per direction. The byte basis is the aggregated skb
	// (docs/architecture/edge-cases.md#tier-2--explicit-handling case
	// 6): payload counts in full, per-segment headers only once per
	// GSO superpacket, so the expected tx delta is N × ~1.00–1.05
	// (worst case: no aggregation, ~66B of headers per ~1400B
	// segment ≈ +4.7%) and the rx delta (pure ACKs) is a few percent
	// of N. 15% headroom absorbs retransmits and background chatter
	// while still failing hard on any systematic overcount — the
	// cheapest double-count bug reads 2×N.
	accuracyUpperBound = accuracyDriveBytes * 115 / 100
)

// byteAccuracyBounds is the catalog's overcount detector. Every other
// assertion is a MinBytes lower bound, so a systematically inflated
// counter (double-counted skbs, a delta applied twice, a fold that
// re-adds) would PASS the whole catalog; this scenario boxes an
// exactly-sized transfer from BOTH sides on a quiet tenant. The SSH
// control traffic that orchestrates the drive rides the external zone
// (via the FIPs), so the same_tenant tuples carry only the stream
// itself and the [N, 1.15N] window is tight.
func byteAccuracyBounds() *scenariotest.Scenario {
	b := scenario.New()
	b.Network("net-T1", "T1").
		Subnet("sub-T1", "10.0.20.0/24", "10.0.20.1").
		VM("vm-a", "T1", "10.0.20.5").
		VM("vm-b", "T1", "10.0.20.6")
	b.ExternalNetwork("net-ext", "admin")
	b.Router("r-T1", "T1").
		Attach("sub-T1", "10.0.20.1").
		ExternalGateway("net-ext")
	return &scenariotest.Scenario{
		Name:    "byte-accuracy-bounds",
		Desc:    "Exact-size transfer boxed in [N, 1.15N] — catches systematic overcounting.",
		Builder: b,
		Steps: []scenariotest.Step{
			steps.CaptureStep{},
			steps.DriveStep{Flows: []scenariotest.Flow{
				{From: "vm-a", To: scenariotest.VMTarget("vm-b"), Bytes: accuracyDriveBytes, Proto: scenariotest.TCP},
			}},
			steps.AssertStep{Note: "lower bound: all driven bytes attributed", Expect: []scenariotest.Expect{
				{TenantID: "T1", Zone: "same_tenant", Direction: "tx", MinBytes: accuracyDriveBytes},
				{TenantID: "T1", Zone: "same_tenant", Direction: "rx", MinBytes: accuracyDriveBytes},
			}},
			// Let the last kernel drain land before reading the ceiling —
			// the assert returns at first pass, mid-drain.
			steps.SleepStep{Duration: 15 * time.Second},
			steps.MaxGrowthStep{Tenant: "T1", Zone: "same_tenant",
				Budget: accuracyUpperBound, Note: "upper bound: no systematic overcount"},
		},
	}
}
