package metadata

import (
	"testing"

	"github.com/bigstack-oss/lachesis/internal/bpf"
)

// macA / macB are locally-administered MACs (low bit of the first
// byte clear). Bit patterns mirror internal/testenv/classifier so
// the kernel-side packing test and the userspace tests speak the
// same language.
var (
	macA = [6]uint8{0x02, 0x00, 0x00, 0x00, 0x00, 0x0A}
	macB = [6]uint8{0x02, 0x00, 0x00, 0x00, 0x00, 0x0B}
)

func TestResolveTenant_Miss(t *testing.T) {
	r := NewResolver(New(), nil)
	key := bpf.FlowKey{SrcMac: macA, DstMac: macB, Direction: bpf.DirectionIngress}
	if got := r.Resolve(key).Tenant; got != "unknown" {
		t.Fatalf("ResolveTenant on empty map = %q, want %q", got, "unknown")
	}
}

func TestResolveTenant_IngressUsesSrcMac(t *testing.T) {
	m := New()
	// Only the SrcMac is in the map; DstMac is the peer (a remote
	// VM whose tenant the Collector doesn't ask about).
	m.Insert(bpf.MACKey(macA), &TenantMeta{ProjectID: "proj-VM-A"})
	r := NewResolver(m, nil)

	key := bpf.FlowKey{SrcMac: macA, DstMac: macB, Direction: bpf.DirectionIngress}
	if got := r.Resolve(key).Tenant; got != "proj-VM-A" {
		t.Fatalf("INGRESS resolve = %q, want %q (SrcMac is the VM)", got, "proj-VM-A")
	}
}

func TestResolveTenant_EgressUsesDstMac(t *testing.T) {
	m := New()
	m.Insert(bpf.MACKey(macB), &TenantMeta{ProjectID: "proj-VM-B"})
	r := NewResolver(m, nil)

	key := bpf.FlowKey{SrcMac: macA, DstMac: macB, Direction: bpf.DirectionEgress}
	if got := r.Resolve(key).Tenant; got != "proj-VM-B" {
		t.Fatalf("EGRESS resolve = %q, want %q (DstMac is the VM)", got, "proj-VM-B")
	}
}

// TestResolveTenant_IngressIgnoresDstMac proves the directional swap:
// even when DstMac is in the map, an INGRESS flow must NOT consult
// it — only SrcMac. Inverting the swap would silently misattribute
// every egress flow.
func TestResolveTenant_IngressIgnoresDstMac(t *testing.T) {
	m := New()
	m.Insert(bpf.MACKey(macB), &TenantMeta{ProjectID: "proj-VM-B"})
	r := NewResolver(m, nil)

	key := bpf.FlowKey{SrcMac: macA, DstMac: macB, Direction: bpf.DirectionIngress}
	if got := r.Resolve(key).Tenant; got != "unknown" {
		t.Fatalf("INGRESS swap broken: resolve = %q, want unknown (SrcMac is absent)", got)
	}
}

// TestResolveTenant_EgressIgnoresSrcMac is the egress mirror of the
// previous test.
func TestResolveTenant_EgressIgnoresSrcMac(t *testing.T) {
	m := New()
	m.Insert(bpf.MACKey(macA), &TenantMeta{ProjectID: "proj-VM-A"})
	r := NewResolver(m, nil)

	key := bpf.FlowKey{SrcMac: macA, DstMac: macB, Direction: bpf.DirectionEgress}
	if got := r.Resolve(key).Tenant; got != "unknown" {
		t.Fatalf("EGRESS swap broken: resolve = %q, want unknown (DstMac is absent)", got)
	}
}

func TestResolveTenant_HitAfterInsertOverwrite(t *testing.T) {
	m := New()
	m.Insert(bpf.MACKey(macA), &TenantMeta{ProjectID: "proj-old"})
	m.Insert(bpf.MACKey(macA), &TenantMeta{ProjectID: "proj-new"})
	r := NewResolver(m, nil)

	key := bpf.FlowKey{SrcMac: macA, Direction: bpf.DirectionIngress}
	if got := r.Resolve(key).Tenant; got != "proj-new" {
		t.Fatalf("ResolveTenant after overwrite = %q, want %q", got, "proj-new")
	}
}

// TestResolve_AttributionFields covers the two fields beyond the
// tenant: ServerID passes through untouched, and ExternalNetwork is
// zone-gated — only EXTERNAL-zone flows of a VM with a resolved
// external path carry a real label; everything else emits the
// NoExternalNetwork sentinel.
func TestResolve_AttributionFields(t *testing.T) {
	m := New()
	m.Insert(bpf.MACKey(macA), &TenantMeta{
		ProjectID: "proj-A", ServerID: "srv-1", ExternalNetwork: "public-1",
	})
	m.Insert(bpf.MACKey(macB), &TenantMeta{ProjectID: "proj-B"})
	r := NewResolver(m, nil)

	cases := []struct {
		name string
		key  bpf.FlowKey
		want Attribution
	}{
		{
			name: "external zone carries the label",
			key:  bpf.FlowKey{SrcMac: macA, Direction: bpf.DirectionIngress, DstZone: bpf.ZoneExternal},
			want: Attribution{Tenant: "proj-A", ServerID: "srv-1", ExternalNetwork: "public-1"},
		},
		{
			name: "non-external zone gates to none",
			key:  bpf.FlowKey{SrcMac: macA, Direction: bpf.DirectionIngress, DstZone: bpf.ZoneSameTenant},
			want: Attribution{Tenant: "proj-A", ServerID: "srv-1", ExternalNetwork: NoExternalNetwork},
		},
		{
			name: "no external path gates to none even on external zone",
			key:  bpf.FlowKey{SrcMac: macB, Direction: bpf.DirectionIngress, DstZone: bpf.ZoneExternal},
			want: Attribution{Tenant: "proj-B", ExternalNetwork: NoExternalNetwork},
		},
		{
			name: "miss returns both sentinels and no server",
			key:  bpf.FlowKey{SrcMac: [6]uint8{0x02, 0xFF, 0, 0, 0, 1}, Direction: bpf.DirectionIngress, DstZone: bpf.ZoneExternal},
			want: Attribution{Tenant: UnknownTenantID, ExternalNetwork: NoExternalNetwork},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := r.Resolve(tc.key); got != tc.want {
				t.Fatalf("Resolve = %+v, want %+v", got, tc.want)
			}
		})
	}
}

// TestExternalNetworkLabel pins the gate as a table: it is the single
// source every emitter (Collector, ghost sweep, reconciler) labels
// through, so its edge behavior is a metric contract.
func TestExternalNetworkLabel(t *testing.T) {
	cases := []struct {
		ext  string
		zone bpf.ZoneCode
		want string
	}{
		{"public-1", bpf.ZoneExternal, "public-1"},
		{"public-1", bpf.ZoneSameTenant, NoExternalNetwork},
		{"public-1", bpf.ZoneOtherTenant, NoExternalNetwork},
		{"public-1", bpf.ZoneInfra, NoExternalNetwork},
		{"public-1", bpf.ZoneShared, NoExternalNetwork},
		{"public-1", bpf.ZoneMiss, NoExternalNetwork},
		{"", bpf.ZoneExternal, NoExternalNetwork},
	}
	for _, tc := range cases {
		if got := ExternalNetworkLabel(tc.ext, tc.zone); got != tc.want {
			t.Errorf("ExternalNetworkLabel(%q, %v) = %q, want %q", tc.ext, tc.zone, got, tc.want)
		}
	}
}
