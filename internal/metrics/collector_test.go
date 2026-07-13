package metrics_test

import (
	"strings"
	"testing"

	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/bpf"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/metadata"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/metrics"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/state"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// Compile-time check: metadata.Resolver must satisfy
// TenantResolver, the interface the Collector calls per Snapshot
// entry. The assertion lives on the consumer side of the seam —
// it cannot live in package metadata's tests anymore, because
// metrics imports metadata (for [metadata.UnknownTenantID]) and
// the reverse test import would cycle.
var _ metrics.TenantResolver = (*metadata.Resolver)(nil)

// stubScraper is a fixed-value [metrics.ScraperStats] for tests.
type stubScraper struct {
	errors uint64
	lastOK int64
}

func (s stubScraper) ErrorCount() uint64     { return s.errors }
func (s stubScraper) LastSuccessUnix() int64 { return s.lastOK }

// staticTenant resolves every key to a fixed tenant id.
type staticTenant string

func (s staticTenant) ResolveTenant(bpf.FlowKey) string { return string(s) }

func keyWith(dir bpf.Direction, zone bpf.ZoneCode) bpf.FlowKey {
	return bpf.FlowKey{
		SrcMac:    [6]uint8{0xaa, 0, 0, 0, 0, 1},
		DstMac:    [6]uint8{0xaa, 0, 0, 0, 0, 2},
		EthProto:  0x0800,
		Direction: dir,
		DstZone:   zone,
	}
}

func TestCollect_EmitsCumulativeBytesAndPackets(t *testing.T) {
	st := state.New()
	st.ApplyDelta(keyWith(bpf.DirectionEgress, bpf.ZoneExternal),
		bpf.FlowMetrics{Bytes: 1000, Packets: 10, LastSeenNs: 1})

	c := metrics.New(st, stubScraper{}, metrics.UnknownTenant{})
	reg := prometheus.NewRegistry()
	reg.MustRegister(c)

	expected := `
# HELP cubecos_bytes_total Network bytes observed by the agent, cumulative since first sight.
# TYPE cubecos_bytes_total counter
cubecos_bytes_total{direction="rx",tenant_id="unknown",zone="external"} 1000
# HELP cubecos_packets_total Network packets observed by the agent, cumulative since first sight.
# TYPE cubecos_packets_total counter
cubecos_packets_total{direction="rx",tenant_id="unknown",zone="external"} 10
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(expected),
		"cubecos_bytes_total", "cubecos_packets_total"); err != nil {
		t.Errorf("GatherAndCompare: %v", err)
	}
}

// TestCollect_DurationHistogramObservesEachPass pins the
// cubecos_collect_duration_seconds exposure. The histogram's sum is
// wall-clock so GatherAndCompare can't pin exact values; sample
// count per Gather is deterministic (one observation per Collect
// pass, emitted within the same pass).
func TestCollect_DurationHistogramObservesEachPass(t *testing.T) {
	c := metrics.New(state.New(), stubScraper{}, metrics.UnknownTenant{})
	reg := prometheus.NewRegistry()
	reg.MustRegister(c)

	for gathers := uint64(1); gathers <= 2; gathers++ {
		mf, err := reg.Gather()
		if err != nil {
			t.Fatalf("Gather %d: %v", gathers, err)
		}
		found := false
		for _, fam := range mf {
			if fam.GetName() != "cubecos_collect_duration_seconds" {
				continue
			}
			found = true
			if got := fam.GetMetric()[0].GetHistogram().GetSampleCount(); got != gathers {
				t.Errorf("gather %d: sample count = %d, want %d", gathers, got, gathers)
			}
		}
		if !found {
			t.Fatalf("gather %d: cubecos_collect_duration_seconds not exposed", gathers)
		}
	}
}

func TestCollect_TenantResolverApplied(t *testing.T) {
	st := state.New()
	st.ApplyDelta(keyWith(bpf.DirectionIngress, bpf.ZoneSameTenant),
		bpf.FlowMetrics{Bytes: 5, Packets: 1, LastSeenNs: 1})

	c := metrics.New(st, stubScraper{}, staticTenant("tenant-abc"))
	reg := prometheus.NewRegistry()
	reg.MustRegister(c)

	mf, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	found := false
	for _, fam := range mf {
		if fam.GetName() != "cubecos_bytes_total" {
			continue
		}
		for _, m := range fam.GetMetric() {
			for _, lbl := range m.GetLabel() {
				if lbl.GetName() == "tenant_id" && lbl.GetValue() == "tenant-abc" {
					found = true
				}
			}
		}
	}
	if !found {
		t.Errorf("tenant_id=tenant-abc not present in emitted metrics")
	}
}

func TestCollect_LabelsCoverAllZonesAndDirections(t *testing.T) {
	cases := []struct {
		dir      bpf.Direction
		zone     bpf.ZoneCode
		wantDir  string
		wantZone string
	}{
		{bpf.DirectionIngress, bpf.ZoneExternal, "tx", "external"},
		{bpf.DirectionEgress, bpf.ZoneSameTenant, "rx", "same_tenant"},
		{bpf.DirectionEgress, bpf.ZoneOtherTenant, "rx", "other_tenant"},
		{bpf.DirectionIngress, bpf.ZoneInfra, "tx", "infra"},
		{bpf.DirectionEgress, bpf.ZoneMiss, "rx", "miss"},
	}

	st := state.New()
	for i, tc := range cases {
		k := keyWith(tc.dir, tc.zone)
		// Distinguish keys by MAC suffix so the map keys do not collide.
		k.SrcMac[5] = byte(i)
		k.DstMac[5] = byte(i + 100)
		st.ApplyDelta(k, bpf.FlowMetrics{Bytes: 1, Packets: 1, LastSeenNs: 1})
	}

	c := metrics.New(st, stubScraper{}, metrics.UnknownTenant{})
	reg := prometheus.NewRegistry()
	reg.MustRegister(c)

	mf, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}

	seen := map[string]bool{}
	for _, fam := range mf {
		if fam.GetName() != "cubecos_bytes_total" {
			continue
		}
		for _, m := range fam.GetMetric() {
			var dir, zone string
			for _, lbl := range m.GetLabel() {
				switch lbl.GetName() {
				case "direction":
					dir = lbl.GetValue()
				case "zone":
					zone = lbl.GetValue()
				}
			}
			seen[dir+"/"+zone] = true
		}
	}
	for _, tc := range cases {
		key := tc.wantDir + "/" + tc.wantZone
		if !seen[key] {
			t.Errorf("missing label combination %q in emitted metrics", key)
		}
	}
}

func TestCollect_UnknownZoneFallsBackToNumeric(t *testing.T) {
	st := state.New()
	k := keyWith(bpf.DirectionEgress, bpf.ZoneCode(99))
	st.ApplyDelta(k, bpf.FlowMetrics{Bytes: 1, Packets: 1, LastSeenNs: 1})

	c := metrics.New(st, stubScraper{}, metrics.UnknownTenant{})
	reg := prometheus.NewRegistry()
	reg.MustRegister(c)

	mf, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	want := false
	for _, fam := range mf {
		if fam.GetName() != "cubecos_bytes_total" {
			continue
		}
		for _, m := range fam.GetMetric() {
			for _, lbl := range m.GetLabel() {
				if lbl.GetName() == "zone" && lbl.GetValue() == "99" {
					want = true
				}
			}
		}
	}
	if !want {
		t.Errorf("expected zone=\"99\" label for unknown zone code 99")
	}
}

func TestCollect_AggregatesFlowsSharingLabels(t *testing.T) {
	// Multiple FlowKeys with different MAC pairs but the same
	// (tenant, zone, direction) label tuple must collapse into one
	// Prometheus sample whose value is the sum.
	st := state.New()
	for i := 0; i < 5; i++ {
		k := keyWith(bpf.DirectionEgress, bpf.ZoneExternal)
		k.SrcMac[5] = byte(i)
		k.DstMac[5] = byte(i + 100)
		st.ApplyDelta(k, bpf.FlowMetrics{Bytes: 100, Packets: 1, LastSeenNs: uint64(i + 1)})
	}

	c := metrics.New(st, stubScraper{}, metrics.UnknownTenant{})
	reg := prometheus.NewRegistry()
	reg.MustRegister(c)

	expected := `
# HELP cubecos_bytes_total Network bytes observed by the agent, cumulative since first sight.
# TYPE cubecos_bytes_total counter
cubecos_bytes_total{direction="rx",tenant_id="unknown",zone="external"} 500
# HELP cubecos_packets_total Network packets observed by the agent, cumulative since first sight.
# TYPE cubecos_packets_total counter
cubecos_packets_total{direction="rx",tenant_id="unknown",zone="external"} 5
# HELP cubecos_state_flows Distinct flow keys currently tracked in GlobalState.
# TYPE cubecos_state_flows gauge
cubecos_state_flows 5
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(expected),
		"cubecos_bytes_total", "cubecos_packets_total", "cubecos_state_flows"); err != nil {
		t.Errorf("GatherAndCompare: %v", err)
	}
}

// TestCollect_SeriesMonotonicAcrossGhostSweep is the headline
// regression for the ghost-sweep re-bucketing bug: a tenant's series
// must expose the same cumulative after its VM's flows are settled and
// its MAC's metadata deleted — not drop, not vanish, not re-bucket to
// "unknown". The sweep itself is exercised in internal/gc; this test
// pins the state+collector contract the fix rests on.
func TestCollect_SeriesMonotonicAcrossGhostSweep(t *testing.T) {
	meta := metadata.New()
	vmMAC := [6]uint8{0xaa, 0, 0, 0, 0, 1}
	macKey := bpf.MACKey(vmMAC)
	meta.Insert(macKey, &metadata.TenantMeta{ProjectID: "tenant-a"})

	st := state.New()
	key := bpf.FlowKey{SrcMac: vmMAC, DstMac: [6]uint8{0xee, 0, 0, 0, 0, 9},
		EthProto: 0x0800, Direction: bpf.DirectionIngress, DstZone: bpf.ZoneSameTenant}
	st.ApplyDelta(key, bpf.FlowMetrics{Bytes: 1000, Packets: 10, LastSeenNs: 1})

	c := metrics.New(st, stubScraper{}, metadata.NewResolver(meta))
	reg := prometheus.NewRegistry()
	reg.MustRegister(c)

	expected := `
# HELP cubecos_bytes_total Network bytes observed by the agent, cumulative since first sight.
# TYPE cubecos_bytes_total counter
cubecos_bytes_total{direction="tx",tenant_id="tenant-a",zone="same_tenant"} 1000
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(expected),
		"cubecos_bytes_total"); err != nil {
		t.Errorf("before sweep: %v", err)
	}

	// The ghost sweep: fold the dead MAC's rows to its tenant, then
	// delete the metadata (the exact order internal/gc performs).
	st.Settle(state.SettleEvict, func(k bpf.FlowKey) (string, bool) {
		if metadata.VMMAC(k) != macKey {
			return "", false
		}
		return "tenant-a", true
	})
	meta.Delete(macKey)

	// The MAC no longer resolves, yet the series is unchanged — the
	// settled bucket carries it. No live flows remain, and nothing
	// re-bucketed to "unknown".
	expected = `
# HELP cubecos_bytes_total Network bytes observed by the agent, cumulative since first sight.
# TYPE cubecos_bytes_total counter
cubecos_bytes_total{direction="tx",tenant_id="tenant-a",zone="same_tenant"} 1000
# HELP cubecos_state_flows Distinct flow keys currently tracked in GlobalState.
# TYPE cubecos_state_flows gauge
cubecos_state_flows 0
# HELP cubecos_state_settled_tuples Distinct (tenant, zone, direction) buckets in the settled-bytes accumulator — flows folded out when their tenant binding was about to disappear (docs/DESIGN.md §3.5).
# TYPE cubecos_state_settled_tuples gauge
cubecos_state_settled_tuples 1
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(expected),
		"cubecos_bytes_total", "cubecos_state_flows", "cubecos_state_settled_tuples"); err != nil {
		t.Errorf("after sweep: %v", err)
	}
}

// TestCollect_MACReuseDoesNotInheritOrReplay is the MAC-reuse
// regression (Bug requirement): a MAC swept under tenant A and later
// reborn on tenant B's port must neither hand A's history to B nor
// count it twice. After the reuse, A holds exactly its settled bytes
// and B counts from the reborn flow's fresh kernel counter only.
func TestCollect_MACReuseDoesNotInheritOrReplay(t *testing.T) {
	meta := metadata.New()
	vmMAC := [6]uint8{0xaa, 0, 0, 0, 0, 1}
	macKey := bpf.MACKey(vmMAC)
	meta.Insert(macKey, &metadata.TenantMeta{ProjectID: "tenant-a"})

	st := state.New()
	key := bpf.FlowKey{SrcMac: vmMAC, DstMac: [6]uint8{0xee, 0, 0, 0, 0, 9},
		EthProto: 0x0800, Direction: bpf.DirectionIngress, DstZone: bpf.ZoneSameTenant}
	st.ApplyDelta(key, bpf.FlowMetrics{Bytes: 1000, Packets: 10, LastSeenNs: 1})

	// Sweep tenant A's VM (fold + evict + metadata delete), then the
	// MAC is reborn on tenant B's port: metadata re-learned, and the
	// reborn flow's kernel counter restarts from zero — its next drain
	// reads a fresh cumulative (300), unrelated to A's 1000.
	st.Settle(state.SettleEvict, func(k bpf.FlowKey) (string, bool) {
		if metadata.VMMAC(k) != macKey {
			return "", false
		}
		return "tenant-a", true
	})
	meta.Delete(macKey)
	meta.Insert(macKey, &metadata.TenantMeta{ProjectID: "tenant-b"})
	st.ApplyDelta(key, bpf.FlowMetrics{Bytes: 300, Packets: 3, LastSeenNs: 2})

	c := metrics.New(st, stubScraper{}, metadata.NewResolver(meta))
	reg := prometheus.NewRegistry()
	reg.MustRegister(c)

	expected := `
# HELP cubecos_bytes_total Network bytes observed by the agent, cumulative since first sight.
# TYPE cubecos_bytes_total counter
cubecos_bytes_total{direction="tx",tenant_id="tenant-a",zone="same_tenant"} 1000
cubecos_bytes_total{direction="tx",tenant_id="tenant-b",zone="same_tenant"} 300
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(expected),
		"cubecos_bytes_total"); err != nil {
		t.Errorf("GatherAndCompare: %v", err)
	}
}

// TestCollect_SettledAndLiveSumPerTuple: when a tenant has both a
// settled bucket and live flows on the same (zone, direction), one
// sample carries the sum — Prometheus rejects duplicate label sets.
func TestCollect_SettledAndLiveSumPerTuple(t *testing.T) {
	st := state.New()
	st.RestoreSettled([]state.SettledRecord{{
		Key:   state.SettledKey{Tenant: "tenant-a", Zone: bpf.ZoneSameTenant, Dir: bpf.DirectionIngress},
		Bytes: 400, Packets: 4,
	}})
	st.ApplyDelta(keyWith(bpf.DirectionIngress, bpf.ZoneSameTenant),
		bpf.FlowMetrics{Bytes: 100, Packets: 1, LastSeenNs: 1})

	c := metrics.New(st, stubScraper{}, staticTenant("tenant-a"))
	reg := prometheus.NewRegistry()
	reg.MustRegister(c)

	expected := `
# HELP cubecos_bytes_total Network bytes observed by the agent, cumulative since first sight.
# TYPE cubecos_bytes_total counter
cubecos_bytes_total{direction="tx",tenant_id="tenant-a",zone="same_tenant"} 500
# HELP cubecos_packets_total Network packets observed by the agent, cumulative since first sight.
# TYPE cubecos_packets_total counter
cubecos_packets_total{direction="tx",tenant_id="tenant-a",zone="same_tenant"} 5
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(expected),
		"cubecos_bytes_total", "cubecos_packets_total"); err != nil {
		t.Errorf("GatherAndCompare: %v", err)
	}
}

func TestCollect_HealthMetrics(t *testing.T) {
	st := state.New()
	st.ApplyDelta(keyWith(bpf.DirectionEgress, bpf.ZoneExternal),
		bpf.FlowMetrics{Bytes: 1, Packets: 1, LastSeenNs: 1})

	c := metrics.New(st, stubScraper{errors: 7, lastOK: 1_700_000_000}, metrics.UnknownTenant{})
	reg := prometheus.NewRegistry()
	reg.MustRegister(c)

	expected := `
# HELP cubecos_scraper_errors_total Cumulative count of failed BPF-map drain attempts since agent start.
# TYPE cubecos_scraper_errors_total counter
cubecos_scraper_errors_total 7
# HELP cubecos_scraper_last_success_unix_seconds Unix timestamp of the most recent successful BPF-map drain; 0 if never.
# TYPE cubecos_scraper_last_success_unix_seconds gauge
cubecos_scraper_last_success_unix_seconds 1.7e+09
# HELP cubecos_state_flows Distinct flow keys currently tracked in GlobalState.
# TYPE cubecos_state_flows gauge
cubecos_state_flows 1
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(expected),
		"cubecos_scraper_errors_total",
		"cubecos_scraper_last_success_unix_seconds",
		"cubecos_state_flows",
	); err != nil {
		t.Errorf("GatherAndCompare: %v", err)
	}
}
