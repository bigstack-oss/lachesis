// mac.go reconciles the kernel mac_tenant_map and the userspace
// metadata map against a fresh Neutron snapshot — the MAC-side
// counterpart of the trie reconcile in reconcile.go. Insertions go
// userspace→kernel; removals are delayed via MarkDelete.
//
// docs/architecture/data-structures.md#map-lifecycle-invariants

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
// mac_tenant_map. Removals are deliberately not its job: a gone MAC
// becomes a lingering ghost and the GC sweeps the kernel entry after
// the grace window.
//
// docs/architecture/data-structures.md#lingering-ghost
type MacWriter interface {
	// value is the packed (Amphora flag ++ tenant id) the kernel stores,
	// built by [bpf.TenantValue] — not a bare tenant id.
	Update(mac uint64, value uint32) error
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
	desired := DesiredMACs(snap)
	inserted, changed := r.learnMACs(desired)
	ghosted := r.ghostGoneMACs(desired, now)
	r.publishAmphoraCount(desired)
	return macDelta{Inserted: inserted, Changed: changed, Ghosted: ghosted}
}

// DesiredMACs maps each admitted VM port to its full attribution — the
// target state of the metadata map. Amphora ports resolve to their load
// balancer's owning project. Ports failing admission are skipped
// silently: a persistently malformed port must not log every pass.
//
// Exported because it is the SINGLE definition of what the map should
// hold, and it has two callers — the reconciler every pass, cold start
// once before any packet. Two implementations would be a billing bug: if
// cold start applied the Amphora rewrite and the reconciler did not, the
// first pass after boot would settle every Amphora port's flows under
// the LB owner and re-attribute to the service project, and the next
// cold start would swing it back.
//
// Diagnostics stay OUT — they belong to cold start's audit pass, which
// produces no attribution and so cannot mis-bill if it drifts.
//
// docs/architecture/octavia.md
func DesiredMACs(snap *neutron.Snapshot) map[uint64]metadata.TenantMeta {
	extByPort := neutron.ExternalNetworkByPort(snap)
	ampByPort := neutron.AmphoraOwnerByPort(snap)
	desired := make(map[uint64]metadata.TenantMeta, len(snap.Ports))
	for _, p := range snap.Ports {
		if !neutron.IsVMPort(p.DeviceOwner) || p.ProjectID == "" || p.MACAddress == "" {
			continue
		}
		hw, err := net.ParseMAC(p.MACAddress)
		if err != nil || len(hw) != 6 {
			continue
		}
		projectID := p.ProjectID
		isAmphora := false
		if owner, ok := ampByPort[p.ID]; ok {
			projectID = owner
			isAmphora = true
		}
		var key [6]uint8
		copy(key[:], hw)
		desired[bpf.MACKey(key)] = metadata.TenantMeta{
			ProjectID:       projectID,
			ServerID:        p.DeviceID,
			PortID:          p.ID,
			ExternalNetwork: extByPort[p.ID],
			IsAmphora:       isAmphora,
		}
	}
	return desired
}

// publishAmphoraCount republishes lachesis_neutron_amphora_ports from the
// desired set — the same quantity cold-start counts, recomputed every
// pass so a load balancer created after boot moves the gauge and a
// deleted one drops it. Without this the metric freezes at its
// cold-start value and silently reports health it cannot know
// (docs/architecture/octavia.md).
func (r *Reconciler) publishAmphoraCount(desired map[uint64]metadata.TenantMeta) {
	if r.amphoraGauge == nil {
		return
	}
	n := 0
	for _, m := range desired {
		if m.IsAmphora {
			n++
		}
	}
	r.amphoraGauge.SetAmphoraPorts(n)
}

// learnMACs inserts every desired MAC that is absent, ghosted, or whose
// attribution changed — userspace first, then kernel. Returns
// (inserted, changed).
//
// Any attribution change settles the MAC's flows under the OLD
// attribution first. The Collector late-binds every label per scrape, so
// skipping the fold re-attributes the MAC's whole history at the next
// one. A ghost resurrected unchanged does not fold.
//
// docs/architecture/data-structures.md#settled-bytes
func (r *Reconciler) learnMACs(desired map[uint64]metadata.TenantMeta) (inserted, changed int) {
	for mac, want := range desired {
		cur, ok := r.meta.Lookup(mac)
		switch {
		case !ok:
			r.insertMAC(mac, want)
			inserted++
		case !cur.SameAttribution(want):
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

// settleAttributionChange folds mac's flow rows into settled under
// old's attribution. Uses [state.SettleRebase], not evict: the port is
// alive and its kernel counters keep running, so the rows must survive
// with LastEbpfRaw intact. Evicting would make the next drain re-count
// the whole kernel cumulative as first sight.
func (r *Reconciler) settleAttributionChange(mac uint64, old *metadata.TenantMeta, want *metadata.TenantMeta) {
	if r.settler == nil {
		return
	}
	// Labels resolve with the current (not-yet-changed) router map —
	// exactly what the Collector was emitting for these rows.
	folded := r.settler.Settle(state.SettleRebase, metadata.SettleResolver(r.routers,
		func(k bpf.FlowKey) (*metadata.TenantMeta, bool) {
			if metadata.VMMAC(k) != mac {
				return nil, false
			}
			return old, true
		}))
	if folded > 0 {
		slog.Info("settled flows to previous attribution before reassignment",
			"component", component, "mac", mac, "flows", folded,
			"old_project", old.ProjectID, "new_project", want.ProjectID,
			"old_external_network", old.ExternalNetwork, "new_external_network", want.ExternalNetwork,
			"old_server", old.ServerID, "new_server", want.ServerID)
	}
}

// insertMAC writes one binding userspace-first then kernel. The
// TenantMeta is replaced whole, never mutated (the immutable
// invariant). A kernel write failure is logged, not fatal — userspace
// already reflects the binding and the next pass retries the kernel
// side.
//
// Map lifecycle: docs/architecture/data-structures.md#map-lifecycle-invariants
func (r *Reconciler) insertMAC(mac uint64, meta metadata.TenantMeta) {
	m := meta // fresh copy per insert; the map owns the pointer
	m.DeleteAt = time.Time{}
	r.meta.Insert(mac, &m)
	if err := r.macWriter.Update(mac, bpf.TenantValue(r.interner.Intern(meta.ProjectID), meta.IsAmphora)); err != nil {
		slog.Warn("reconcile mac_tenant_map kernel write failed; retry next pass",
			"component", component, "mac", mac, "err", err)
	}
}

// ghostGoneMACs MarkDeletes every live entry whose MAC left desired,
// starting its grace window. Collects under Range and marks afterwards:
// MarkDelete takes a shard write lock that Range holds as a read lock.
// Already-ghosted entries keep their original deadline.
//
// docs/architecture/data-structures.md#lingering-ghost
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
		r.meta.MarkDelete(mac, now.Add(r.tun.Get().GhostGrace))
	}
	return len(gone)
}
