// routers.go reconciles the router-interface-MAC → external-network
// map behind the per-flow external attribution (docs/architecture/billing.md).
// Like the MAC reconcile, any attribution change settles the affected
// flows under the OLD label before the new state is published, so the
// exposed external_network series stay monotone through router
// re-gatewaying.

package reconcile

import (
	"log/slog"

	"github.com/bigstack-oss/lachesis/internal/bpf"
	"github.com/bigstack-oss/lachesis/internal/metadata"
	"github.com/bigstack-oss/lachesis/internal/neutron"
	"github.com/bigstack-oss/lachesis/internal/state"
)

// reconcileRouterMACs rebuilds the desired router map from the
// snapshot, diffs it against the published one, and swaps it in.
// Every CHANGED interface MAC — label changed (router re-gatewayed),
// mapping gone (gateway cleared / interface removed), or mapping new
// (would shadow the per-VM fallback) — first has the live flows riding
// it folded into the settled accumulator under the label the Collector
// was emitting ([state.SettleRebase]: the ports are alive, kernel
// counters keep running, watermarks must survive). The fold reads the
// NOT-yet-swapped map, so old labels are computed with exactly the
// state the last scrape used. Returns the number of changed MACs.
// No-op when no router store is wired (trie-only unit tests).
func (r *Reconciler) reconcileRouterMACs(snap *neutron.Snapshot) int {
	if r.routers == nil {
		return 0
	}
	desired := neutron.RouterExtMACs(snap)
	old := r.routers.Snapshot()
	changed := make(map[uint64]bool)
	for mac, ext := range desired {
		if oldExt, ok := old[mac]; !ok || oldExt != ext {
			changed[mac] = true
		}
	}
	for mac := range old {
		if _, ok := desired[mac]; !ok {
			changed[mac] = true
		}
	}
	if len(changed) == 0 {
		return 0
	}

	folded := 0
	if r.settler != nil && r.meta != nil {
		folded = r.settler.Settle(state.SettleRebase, metadata.SettleResolver(r.routers,
			func(k bpf.FlowKey) (*metadata.TenantMeta, bool) {
				if k.DstZone != bpf.ZoneExternal || !changed[metadata.PeerMAC(k)] {
					return nil, false
				}
				// Unknown-VM flows emit the sentinel label regardless of
				// the router map (the Resolver misses before consulting
				// it) — nothing to re-home.
				return r.meta.Lookup(metadata.VMMAC(k))
			}))
	}
	r.routers.Replace(desired)
	slog.Info("router external-network map updated; affected flows settled under their old label",
		"component", component, "changed_macs", len(changed), "flows_folded", folded)
	return len(changed)
}
