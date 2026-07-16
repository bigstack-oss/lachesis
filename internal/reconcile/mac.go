// mac.go reconciles the kernel mac_tenant_map and the userspace metadata
// map against a fresh Neutron snapshot — the MAC-side counterpart of the
// subnet_zone_trie reconcile in reconcile.go. Where the trie diff is a
// pure kernel write, the MAC reconcile drives the lingering-ghost
// lifecycle (docs/DESIGN.md §3.3/§3.4): insertions go userspace→kernel,
// removals are delayed via MarkDelete rather than deleted outright.

package reconcile

import (
	"log/slog"
	"net"
	"time"

	"github.com/bigstack-oss/lachesis/internal/bpf"
	"github.com/bigstack-oss/lachesis/internal/metadata"
	"github.com/bigstack-oss/lachesis/internal/neutron"
	"github.com/bigstack-oss/lachesis/internal/state"
)

// MacWriter writes one (mac → tenant id) binding into the kernel
// mac_tenant_map. The reconcile worker inserts learned MACs through it;
// removals are deliberately NOT its job — a gone MAC becomes a lingering
// ghost (userspace MarkDelete) and the GC sweeps the kernel entry after
// the grace window (docs/DESIGN.md §3.3). The agent wires an *ebpf.Map
// adapter; tests wire a recording mock.
type MacWriter interface {
	Update(mac uint64, tenantID uint32) error
}

// macDelta counts what one MAC reconcile pass changed.
type macDelta struct {
	Inserted int // newly-learned MACs
	Changed  int // attribution changed, or a ghost resurrected
	Ghosted  int // gone ports MarkDeleted (grace started)
}

// reconcileMACs brings the mac_tenant_map and metadata map in line with
// the VM ports in the snapshot. Orchestration only; the load-bearing part
// is the order — learn (insert) then ghost (MarkDelete) — so a tenant
// whose MAC moved (delete+recreate in one snapshot) is re-learned before
// the stale entry is ghosted. Skips entirely when no metadata map or
// kernel writer is wired (unit tests that exercise only the trie path).
func (r *Reconciler) reconcileMACs(snap *neutron.Snapshot, now time.Time) macDelta {
	if r.meta == nil || r.macWriter == nil {
		return macDelta{}
	}
	desired := desiredMACs(snap)
	inserted, changed := r.learnMACs(desired)
	ghosted := r.ghostGoneMACs(desired, now)
	return macDelta{Inserted: inserted, Changed: changed, Ghosted: ghosted}
}

// desiredMACs maps each admitted VM port to its full attribution — the
// target state of the metadata map (the kernel mac_tenant_map carries
// only the tenant slice of it). It mirrors the cold-start admission gate
// (neutron.IsVMPort plus a parseable MAC and a project); ports failing it
// are skipped silently, because first-time admission logging is
// cold-start's job and a persistently malformed port must not log every
// pass. ServerID and ExternalNetwork ride along so the per-server export
// and the external_network label stay current between cold starts
// (docs/DESIGN.md §11.5).
func desiredMACs(snap *neutron.Snapshot) map[uint64]metadata.TenantMeta {
	extByPort := neutron.ExternalNetworkByPort(snap)
	desired := make(map[uint64]metadata.TenantMeta, len(snap.Ports))
	for _, p := range snap.Ports {
		if !neutron.IsVMPort(p.DeviceOwner) || p.ProjectID == "" || p.MACAddress == "" {
			continue
		}
		hw, err := net.ParseMAC(p.MACAddress)
		if err != nil || len(hw) != 6 {
			continue
		}
		var key [6]uint8
		copy(key[:], hw)
		desired[bpf.MACKey(key)] = metadata.TenantMeta{
			ProjectID:       p.ProjectID,
			ServerID:        p.DeviceID,
			ExternalNetwork: extByPort[p.ID],
		}
	}
	return desired
}

// learnMACs inserts every desired MAC that is absent, ghosted, or whose
// attribution changed — userspace first, then kernel (docs/DESIGN.md
// §3.4). Learning a previously-unknown MAC is what lets the next scrape
// resolve its buffered flows. Returns (inserted, changed); an entry
// already live with the same attribution is left untouched.
//
// Any attribution change — tenant, external network, or server binding —
// settles the MAC's accumulated flows under the OLD attribution before
// the binding is replaced: the Collector late-binds all three labels per
// scrape, so without the fold the MAC's whole history would re-attribute
// at the next scrape — the tenant case re-bills another project
// (docs/DESIGN.md §3.5), the external-network case teleports bytes
// between external_network series (breaking their monotonicity), and the
// server case re-mints the old server's cumulative under the new
// server_id (over-billing it in the per-server export's born-series
// rule, §11.5). A ghost resurrected with identical attribution does not
// fold — its history still belongs where it is.
func (r *Reconciler) learnMACs(desired map[uint64]metadata.TenantMeta) (inserted, changed int) {
	for mac, want := range desired {
		cur, ok := r.meta.Lookup(mac)
		switch {
		case !ok:
			r.insertMAC(mac, want)
			inserted++
		case cur.ProjectID != want.ProjectID ||
			cur.ExternalNetwork != want.ExternalNetwork ||
			cur.ServerID != want.ServerID:
			// Attribution changed (possibly a ghost resurrected under a
			// new attribution): settle history under the old one first.
			r.settleAttributionChange(mac, cur, &want)
			r.insertMAC(mac, want)
			changed++
		case !cur.DeleteAt.IsZero():
			// A ghost came back within its grace, same attribution.
			r.insertMAC(mac, want)
			changed++
		}
	}
	return inserted, changed
}

// settleAttributionChange folds mac's GlobalState flow rows into the
// settled accumulator under old's attribution — tenant plus the
// zone-gated external_network label, so each row's bytes land in exactly
// the series they were being emitted on. The fold uses
// [state.SettleRebase] — the port is alive and its kernel telemetry_map
// counters keep running, so the rows must survive with their LastEbpfRaw
// watermarks intact: the next drain then credits only bytes that arrived
// after the fold, and those late-bind to the new attribution. Evicting
// the rows instead would make the next drain re-count the full kernel
// cumulative as first sight — double-billing the new attribution with
// the old one's bytes.
func (r *Reconciler) settleAttributionChange(mac uint64, old *metadata.TenantMeta, want *metadata.TenantMeta) {
	if r.settler == nil {
		return
	}
	folded := r.settler.Settle(state.SettleRebase, func(k bpf.FlowKey) (string, string, bool) {
		if metadata.VMMAC(k) != mac {
			return "", "", false
		}
		// Per-flow label with the current (not-yet-changed) router map —
		// exactly what the Collector was emitting for this row.
		return old.ProjectID, metadata.FlowExternalLabel(r.routers, old.ExternalNetwork, k), true
	})
	if folded > 0 {
		slog.Info("settled flows to previous attribution before reassignment",
			"component", component, "mac", mac, "flows", folded,
			"old_project", old.ProjectID, "new_project", want.ProjectID,
			"old_external_network", old.ExternalNetwork, "new_external_network", want.ExternalNetwork,
			"old_server", old.ServerID, "new_server", want.ServerID)
	}
}

// insertMAC writes one binding userspace-first then kernel (docs/DESIGN.md
// §3.4). The TenantMeta is replaced whole, never mutated (the immutable
// invariant). A kernel write failure is logged, not fatal — userspace
// already reflects the binding and the next pass retries the kernel side.
func (r *Reconciler) insertMAC(mac uint64, meta metadata.TenantMeta) {
	m := meta // fresh copy per insert; the map owns the pointer
	m.DeleteAt = time.Time{}
	r.meta.Insert(mac, &m)
	if err := r.macWriter.Update(mac, r.interner.Intern(meta.ProjectID)); err != nil {
		slog.Warn("reconcile mac_tenant_map kernel write failed; retry next pass",
			"component", component, "mac", mac, "err", err)
	}
}

// ghostGoneMACs MarkDeletes every live metadata entry whose MAC is no
// longer in desired, starting its lingering-ghost grace (docs/DESIGN.md
// §3.3) — the agent's first production MarkDelete caller. It collects
// under Range and marks afterwards: MarkDelete takes a shard write lock
// that Range holds as a read lock. Already-ghosted entries are left alone
// so their original grace keeps running.
func (r *Reconciler) ghostGoneMACs(desired map[uint64]metadata.TenantMeta, now time.Time) int {
	var gone []uint64
	r.meta.Range(func(mac uint64, m *metadata.TenantMeta) bool {
		if m.DeleteAt.IsZero() {
			if _, want := desired[mac]; !want {
				gone = append(gone, mac)
			}
		}
		return true
	})
	for _, mac := range gone {
		r.meta.MarkDelete(mac, now.Add(r.graceNow()))
	}
	return len(gone)
}
