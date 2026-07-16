package metadata

import (
	"sync/atomic"

	"github.com/bigstack-oss/lachesis/internal/bpf"
)

// RouterMACs holds the router-interface-MAC → external-network-label
// map behind an atomic pointer: one owner (the reconciler, seeded by
// cold start) replaces the whole map per sync; readers (the Collector's
// per-row resolution, the settle folds) load it lock-free. The
// population is small — one entry per gatewayed router interface — so
// whole-map replacement per pass is cheaper than any locking scheme,
// and the swap gives readers a consistent view by construction.
type RouterMACs struct {
	v atomic.Pointer[map[uint64]string]
}

// NewRouterMACs returns an empty store; lookups miss until the first
// Replace (cold start, before any scrape — the boot order guarantees
// it).
func NewRouterMACs() *RouterMACs {
	r := &RouterMACs{}
	empty := map[uint64]string{}
	r.v.Store(&empty)
	return r
}

// Replace swaps the whole map in. The caller must not mutate m after
// handing it over — readers hold the pointer.
func (r *RouterMACs) Replace(m map[uint64]string) {
	r.v.Store(&m)
}

// Lookup resolves a peer MAC to its router's external-network label.
// Zero-alloc: one atomic load and one map read (the Collect hot-path
// constraint).
func (r *RouterMACs) Lookup(mac uint64) (string, bool) {
	ext, ok := (*r.v.Load())[mac]
	return ext, ok
}

// Snapshot returns the current map for diffing. Read-only by the same
// contract as Replace.
func (r *RouterMACs) Snapshot() map[uint64]string {
	return *r.v.Load()
}

// PeerMAC returns the non-VM-side MAC of key — the remote endpoint's
// MAC at the tap, which for routed traffic is a router interface's. It
// is [VMMAC]'s mirror under the same directional swap and lives beside
// it so the swap rule stays in exactly one file.
func PeerMAC(key bpf.FlowKey) uint64 {
	if key.Direction == bpf.DirectionIngress {
		return bpf.MACKey(key.DstMac)
	}
	return bpf.MACKey(key.SrcMac)
}

// FlowExternalLabel resolves the external_network label for one flow:
// per-flow via the peer router-interface MAC when the router map knows
// it (the network that actually carried the flow), else the per-VM
// attribution (FIP / gateway-IP rule), both behind the
// [ExternalNetworkLabel] zone gate. Single source for every emitter —
// the Collector's live aggregation, the ghost sweep's settle fold, and
// the reconciler's attribution-change folds all label through here, so
// a flow's settled bytes land in exactly the bucket its live series
// occupied. routers may be nil (tests without a router map): pure
// per-VM fallback.
func FlowExternalLabel(routers *RouterMACs, vmExtNet string, key bpf.FlowKey) string {
	if key.DstZone != bpf.ZoneExternal {
		return NoExternalNetwork
	}
	if routers != nil {
		if ext, ok := routers.Lookup(PeerMAC(key)); ok {
			return ext
		}
	}
	return ExternalNetworkLabel(vmExtNet, key.DstZone)
}
