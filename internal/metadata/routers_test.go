package metadata

import (
	"testing"

	"github.com/bigstack-oss/lachesis/internal/bpf"
)

var (
	vmM   = [6]uint8{0xaa, 0, 0, 0, 0, 1}
	rtrM  = [6]uint8{0xfa, 0x16, 0x3e, 0, 0, 0x10}
	rtrM2 = [6]uint8{0xfa, 0x16, 0x3e, 0, 0, 0x20}
)

func extKey(peer [6]uint8, zone bpf.ZoneCode) bpf.FlowKey {
	return bpf.FlowKey{SrcMac: vmM, DstMac: peer, Direction: bpf.DirectionIngress, DstZone: zone}
}

// TestPeerMAC pins the mirror of the directional swap: on INGRESS the
// peer is the destination, on EGRESS the source — always the opposite
// side from [VMMAC].
func TestPeerMAC(t *testing.T) {
	in := bpf.FlowKey{SrcMac: vmM, DstMac: rtrM, Direction: bpf.DirectionIngress}
	if PeerMAC(in) != bpf.MACKey(rtrM) || VMMAC(in) != bpf.MACKey(vmM) {
		t.Errorf("INGRESS: peer=%x vm=%x, want dst/src", PeerMAC(in), VMMAC(in))
	}
	out := bpf.FlowKey{SrcMac: rtrM, DstMac: vmM, Direction: bpf.DirectionEgress}
	if PeerMAC(out) != bpf.MACKey(rtrM) || VMMAC(out) != bpf.MACKey(vmM) {
		t.Errorf("EGRESS: peer=%x vm=%x, want src/dst", PeerMAC(out), VMMAC(out))
	}
}

// TestFlowExternalLabel is the per-flow label rule as a table: router
// hit wins, per-VM attribution is the fallback, the zone gate trumps
// everything, and a nil store degrades to pure per-VM.
func TestFlowExternalLabel(t *testing.T) {
	routers := NewRouterMACs()
	routers.Replace(map[uint64]string{bpf.MACKey(rtrM): "public-1"})

	cases := []struct {
		name    string
		routers *RouterMACs
		vmExt   string
		key     bpf.FlowKey
		want    string
	}{
		{"router hit wins over per-VM", routers, "public-2", extKey(rtrM, bpf.ZoneExternal), "public-1"},
		{"unknown peer falls back to per-VM", routers, "public-2", extKey(rtrM2, bpf.ZoneExternal), "public-2"},
		{"unknown peer, no per-VM path -> sentinel", routers, "", extKey(rtrM2, bpf.ZoneExternal), NoExternalNetwork},
		{"non-external zone gates to sentinel even on router hit", routers, "public-2", extKey(rtrM, bpf.ZoneSameTenant), NoExternalNetwork},
		{"nil store -> per-VM only", nil, "public-2", extKey(rtrM, bpf.ZoneExternal), "public-2"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := FlowExternalLabel(tc.routers, tc.vmExt, tc.key); got != tc.want {
				t.Fatalf("FlowExternalLabel = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestResolver_PerFlowRouterAttribution: one VM, two external flows via
// different routers — each resolves to the network that carried it;
// the per-VM attribution only covers the unknown-router flow.
func TestResolver_PerFlowRouterAttribution(t *testing.T) {
	m := New()
	m.Insert(bpf.MACKey(vmM), &TenantMeta{ProjectID: "proj-A", ServerID: "srv-1", ExternalNetwork: "public-2"})
	routers := NewRouterMACs()
	routers.Replace(map[uint64]string{
		bpf.MACKey(rtrM):  "public-1",
		bpf.MACKey(rtrM2): "public-3",
	})
	r := NewResolver(m, routers)

	if got := r.Resolve(extKey(rtrM, bpf.ZoneExternal)); got.ExternalNetwork != "public-1" {
		t.Errorf("flow via rtr-1 = %q, want public-1", got.ExternalNetwork)
	}
	if got := r.Resolve(extKey(rtrM2, bpf.ZoneExternal)); got.ExternalNetwork != "public-3" {
		t.Errorf("flow via rtr-2 = %q, want public-3", got.ExternalNetwork)
	}
	unknownPeer := extKey([6]uint8{0xee, 0, 0, 0, 0, 9}, bpf.ZoneExternal)
	if got := r.Resolve(unknownPeer); got.ExternalNetwork != "public-2" {
		t.Errorf("provider-direct flow = %q, want per-VM public-2", got.ExternalNetwork)
	}
}

// TestResolver_UnknownVMSkipsRouterMap: an unresolved VM MAC returns
// both sentinels even when the peer router is known — emission and the
// settle folds agree that unknown-tenant traffic carries no
// external_network (the fold callbacks skip such rows).
func TestResolver_UnknownVMSkipsRouterMap(t *testing.T) {
	routers := NewRouterMACs()
	routers.Replace(map[uint64]string{bpf.MACKey(rtrM): "public-1"})
	r := NewResolver(New(), routers)

	got := r.Resolve(extKey(rtrM, bpf.ZoneExternal))
	if got.Tenant != UnknownTenantID || got.ExternalNetwork != NoExternalNetwork {
		t.Fatalf("unknown VM = %+v, want unknown/none", got)
	}
}
