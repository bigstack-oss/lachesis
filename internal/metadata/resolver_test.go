package metadata

import (
	"testing"

	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/bpf"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/metrics"
)

// Compile-time check: Resolver must satisfy metrics.TenantResolver,
// the interface the Collector calls per Snapshot entry. Asserting
// the seam here means a future rename / signature change fails the
// test build of *this* package, not silently at a different wiring
// point.
var _ metrics.TenantResolver = (*Resolver)(nil)

// macA / macB are locally-administered MACs (low bit of the first
// byte clear). Bit patterns mirror internal/testenv/classifier so
// the kernel-side packing test and the userspace tests speak the
// same language.
var (
	macA = [6]uint8{0x02, 0x00, 0x00, 0x00, 0x00, 0x0A}
	macB = [6]uint8{0x02, 0x00, 0x00, 0x00, 0x00, 0x0B}
)

func TestResolveTenant_Miss(t *testing.T) {
	r := NewResolver(New())
	key := bpf.FlowKey{SrcMac: macA, DstMac: macB, Direction: bpf.DirectionIngress}
	if got := r.ResolveTenant(key); got != "unknown" {
		t.Fatalf("ResolveTenant on empty map = %q, want %q", got, "unknown")
	}
}

func TestResolveTenant_IngressUsesSrcMac(t *testing.T) {
	m := New()
	// Only the SrcMac is in the map; DstMac is the peer (a remote
	// VM whose tenant the Collector doesn't ask about).
	m.Insert(bpf.MACKey(macA), &TenantMeta{ProjectID: "proj-VM-A"})
	r := NewResolver(m)

	key := bpf.FlowKey{SrcMac: macA, DstMac: macB, Direction: bpf.DirectionIngress}
	if got := r.ResolveTenant(key); got != "proj-VM-A" {
		t.Fatalf("INGRESS resolve = %q, want %q (SrcMac is the VM)", got, "proj-VM-A")
	}
}

func TestResolveTenant_EgressUsesDstMac(t *testing.T) {
	m := New()
	m.Insert(bpf.MACKey(macB), &TenantMeta{ProjectID: "proj-VM-B"})
	r := NewResolver(m)

	key := bpf.FlowKey{SrcMac: macA, DstMac: macB, Direction: bpf.DirectionEgress}
	if got := r.ResolveTenant(key); got != "proj-VM-B" {
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
	r := NewResolver(m)

	key := bpf.FlowKey{SrcMac: macA, DstMac: macB, Direction: bpf.DirectionIngress}
	if got := r.ResolveTenant(key); got != "unknown" {
		t.Fatalf("INGRESS swap broken: resolve = %q, want unknown (SrcMac is absent)", got)
	}
}

// TestResolveTenant_EgressIgnoresSrcMac is the egress mirror of the
// previous test.
func TestResolveTenant_EgressIgnoresSrcMac(t *testing.T) {
	m := New()
	m.Insert(bpf.MACKey(macA), &TenantMeta{ProjectID: "proj-VM-A"})
	r := NewResolver(m)

	key := bpf.FlowKey{SrcMac: macA, DstMac: macB, Direction: bpf.DirectionEgress}
	if got := r.ResolveTenant(key); got != "unknown" {
		t.Fatalf("EGRESS swap broken: resolve = %q, want unknown (DstMac is absent)", got)
	}
}

func TestResolveTenant_HitAfterInsertOverwrite(t *testing.T) {
	m := New()
	m.Insert(bpf.MACKey(macA), &TenantMeta{ProjectID: "proj-old"})
	m.Insert(bpf.MACKey(macA), &TenantMeta{ProjectID: "proj-new"})
	r := NewResolver(m)

	key := bpf.FlowKey{SrcMac: macA, Direction: bpf.DirectionIngress}
	if got := r.ResolveTenant(key); got != "proj-new" {
		t.Fatalf("ResolveTenant after overwrite = %q, want %q", got, "proj-new")
	}
}
