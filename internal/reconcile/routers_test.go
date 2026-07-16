package reconcile

import (
	"net"
	"testing"
	"time"

	"github.com/bigstack-oss/lachesis/internal/bpf"
	"github.com/bigstack-oss/lachesis/internal/metadata"
	"github.com/bigstack-oss/lachesis/internal/neutron"
	"github.com/bigstack-oss/lachesis/internal/state"
	"github.com/bigstack-oss/lachesis/internal/tunables"
)

// routerSnap declares one gatewayed router (rtr-1, interface MAC
// rtrMAC) on external network extID/extName.
func routerSnap(rtrMAC, extID, extName string) neutron.Snapshot {
	return neutron.Snapshot{
		Networks: []neutron.Network{{ID: extID, Name: extName, IsExternal: true}},
		Routers:  []neutron.Router{{ID: "rtr-1", ExternalNetworkID: extID}},
		Ports: []neutron.Port{{
			ID: "p-rtr", DeviceOwner: neutron.DeviceOwnerRouterInterface,
			DeviceID: "rtr-1", MACAddress: rtrMAC,
		}},
	}
}

func extFlowKey(t *testing.T, vmMAC, peerMAC string) bpf.FlowKey {
	t.Helper()
	var src, dst [6]uint8
	hw, err := net.ParseMAC(vmMAC)
	if err != nil {
		t.Fatal(err)
	}
	copy(src[:], hw)
	if hw, err = net.ParseMAC(peerMAC); err != nil {
		t.Fatal(err)
	}
	copy(dst[:], hw)
	return bpf.FlowKey{SrcMac: src, DstMac: dst, EthProto: 0x0800,
		Direction: bpf.DirectionIngress, DstZone: bpf.ZoneExternal}
}

// TestReconcileRouterMACs_GatewayChangeSettlesOldLabel: a router
// re-gatewayed to another external network folds the flows riding its
// interface MAC under the OLD label (SettleRebase — rows survive with
// watermarks) before the map swap; the swap then resolves new traffic
// to the new label.
func TestReconcileRouterMACs_GatewayChangeSettlesOldLabel(t *testing.T) {
	const vmMAC, rtrMAC = "aa:00:00:00:00:01", "fa:16:3e:00:00:10"
	meta := metadata.New()
	meta.Insert(mac(t, vmMAC), &metadata.TenantMeta{ProjectID: "proj-a"})

	routers := metadata.NewRouterMACs()
	routers.Replace(map[uint64]string{mac(t, rtrMAC): "public-1"})

	st := state.New()
	st.ApplyDelta(extFlowKey(t, vmMAC, rtrMAC), bpf.FlowMetrics{Bytes: 700, Packets: 7, LastSeenNs: 1})

	r := New(Options{
		Tunables: tunables.New(tunables.Values{GhostGrace: 60 * time.Second, ReconcileInterval: time.Minute}),

		Meta: meta, Routers: routers, Settler: st,
		Interner: metadata.NewTenantInterner(), Metrics: NewMetrics(),
	})
	snap := routerSnap(rtrMAC, "net-pub2", "public-2")
	if n := r.reconcileRouterMACs(&snap); n != 1 {
		t.Fatalf("changed MACs = %d, want 1", n)
	}

	flows, settled := st.SnapshotWithSettled(nil, nil)
	if len(flows) != 1 {
		t.Fatalf("flows = %+v, want the row to SURVIVE (SettleRebase)", flows)
	}
	wantKey := state.SettledKey{Tenant: "proj-a", ExtNet: "public-1", Zone: bpf.ZoneExternal, Dir: bpf.DirectionIngress}
	if len(settled) != 1 || settled[0].Key != wantKey || settled[0].Bytes != 700 {
		t.Fatalf("settled = %+v, want 700 bytes under OLD label %+v", settled, wantKey)
	}
	if ext, ok := routers.Lookup(mac(t, rtrMAC)); !ok || ext != "public-2" {
		t.Errorf("post-swap lookup = %q/%v, want public-2", ext, ok)
	}
}

// TestReconcileRouterMACs_NoChangeNoFold: an identical desired map is
// a no-op — no fold, no churn.
func TestReconcileRouterMACs_NoChangeNoFold(t *testing.T) {
	const vmMAC, rtrMAC = "aa:00:00:00:00:01", "fa:16:3e:00:00:10"
	meta := metadata.New()
	meta.Insert(mac(t, vmMAC), &metadata.TenantMeta{ProjectID: "proj-a"})
	routers := metadata.NewRouterMACs()
	routers.Replace(map[uint64]string{mac(t, rtrMAC): "public-1"})
	st := state.New()
	st.ApplyDelta(extFlowKey(t, vmMAC, rtrMAC), bpf.FlowMetrics{Bytes: 700, Packets: 7, LastSeenNs: 1})

	r := New(Options{
		Tunables: tunables.New(tunables.Values{GhostGrace: 60 * time.Second, ReconcileInterval: time.Minute}),

		Meta: meta, Routers: routers, Settler: st,
		Interner: metadata.NewTenantInterner(), Metrics: NewMetrics(),
	})
	snap := routerSnap(rtrMAC, "net-pub1", "public-1")
	if n := r.reconcileRouterMACs(&snap); n != 0 {
		t.Fatalf("changed MACs = %d, want 0", n)
	}
	if _, settled := st.SnapshotWithSettled(nil, nil); len(settled) != 0 {
		t.Errorf("no-change pass folded rows: %+v", settled)
	}
}

// TestReconcileRouterMACs_RemovalFoldsAndForgets: a router losing its
// gateway removes the mapping — its flows fold under the old label
// first, and later lookups miss (per-VM fallback takes over).
func TestReconcileRouterMACs_RemovalFoldsAndForgets(t *testing.T) {
	const vmMAC, rtrMAC = "aa:00:00:00:00:01", "fa:16:3e:00:00:10"
	meta := metadata.New()
	meta.Insert(mac(t, vmMAC), &metadata.TenantMeta{ProjectID: "proj-a"})
	routers := metadata.NewRouterMACs()
	routers.Replace(map[uint64]string{mac(t, rtrMAC): "public-1"})
	st := state.New()
	st.ApplyDelta(extFlowKey(t, vmMAC, rtrMAC), bpf.FlowMetrics{Bytes: 500, Packets: 5, LastSeenNs: 1})

	r := New(Options{
		Tunables: tunables.New(tunables.Values{GhostGrace: 60 * time.Second, ReconcileInterval: time.Minute}),

		Meta: meta, Routers: routers, Settler: st,
		Interner: metadata.NewTenantInterner(), Metrics: NewMetrics(),
	})
	snap := routerSnap(rtrMAC, "net-pub1", "public-1")
	snap.Routers[0].ExternalNetworkID = "" // gateway cleared
	if n := r.reconcileRouterMACs(&snap); n != 1 {
		t.Fatalf("changed MACs = %d, want 1", n)
	}
	_, settled := st.SnapshotWithSettled(nil, nil)
	if len(settled) != 1 || settled[0].Key.ExtNet != "public-1" || settled[0].Bytes != 500 {
		t.Fatalf("settled = %+v, want 500 bytes under public-1", settled)
	}
	if _, ok := routers.Lookup(mac(t, rtrMAC)); ok {
		t.Error("cleared gateway must remove the mapping")
	}
}

// TestReconcileRouterMACs_NonExternalAndForeignRowsUntouched: the fold
// targets only external-zone rows riding a CHANGED router MAC — other
// zones and other peers stay live.
func TestReconcileRouterMACs_NonExternalAndForeignRowsUntouched(t *testing.T) {
	const vmMAC, rtrMAC, otherMAC = "aa:00:00:00:00:01", "fa:16:3e:00:00:10", "fa:16:3e:00:00:99"
	meta := metadata.New()
	meta.Insert(mac(t, vmMAC), &metadata.TenantMeta{ProjectID: "proj-a"})
	routers := metadata.NewRouterMACs()
	routers.Replace(map[uint64]string{mac(t, rtrMAC): "public-1"})
	st := state.New()
	same := extFlowKey(t, vmMAC, rtrMAC)
	same.DstZone = bpf.ZoneSameTenant
	st.ApplyDelta(same, bpf.FlowMetrics{Bytes: 100, Packets: 1, LastSeenNs: 1})
	st.ApplyDelta(extFlowKey(t, vmMAC, otherMAC), bpf.FlowMetrics{Bytes: 200, Packets: 2, LastSeenNs: 2})

	r := New(Options{
		Tunables: tunables.New(tunables.Values{GhostGrace: 60 * time.Second, ReconcileInterval: time.Minute}),

		Meta: meta, Routers: routers, Settler: st,
		Interner: metadata.NewTenantInterner(), Metrics: NewMetrics(),
	})
	snap := routerSnap(rtrMAC, "net-pub2", "public-2")
	r.reconcileRouterMACs(&snap)

	flows, settled := st.SnapshotWithSettled(nil, nil)
	if len(settled) != 0 {
		t.Errorf("folded rows that don't ride the changed router: %+v", settled)
	}
	if len(flows) != 2 {
		t.Errorf("flows = %+v, want both untouched", flows)
	}
}
