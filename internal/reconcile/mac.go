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

	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/bpf"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/metadata"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/neutron"
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
	Changed  int // tenant changed, or a ghost resurrected
	Ghosted  int // gone ports MarkDeleted (grace started)
}

// reconcileMACs brings the mac_tenant_map and metadata map in line with
// the VM ports in the snapshot. Orchestration only; the load-bearing part
// is the order — learn (insert) then ghost (MarkDelete) — so a tenant
// whose MAC moved (delete+recreate in one snapshot) is re-learned before
// the stale entry is ghosted. Skips entirely when no metadata map or
// kernel writer is wired (unit tests that exercise only the trie path).
func (r *Reconciler) reconcileMACs(ports []neutron.Port, now time.Time) macDelta {
	if r.meta == nil || r.macWriter == nil {
		return macDelta{}
	}
	desired := desiredMACs(ports)
	inserted, changed := r.learnMACs(desired)
	ghosted := r.ghostGoneMACs(desired, now)
	return macDelta{Inserted: inserted, Changed: changed, Ghosted: ghosted}
}

// desiredMACs maps each admitted VM port to its project — the target
// state of the mac_tenant_map. It mirrors the cold-start admission gate
// (neutron.IsVMPort plus a parseable MAC and a project); ports failing it
// are skipped silently, because first-time admission logging is
// cold-start's job and a persistently malformed port must not log every
// pass.
func desiredMACs(ports []neutron.Port) map[uint64]string {
	desired := make(map[uint64]string, len(ports))
	for _, p := range ports {
		if !neutron.IsVMPort(p.DeviceOwner) || p.ProjectID == "" || p.MACAddress == "" {
			continue
		}
		hw, err := net.ParseMAC(p.MACAddress)
		if err != nil || len(hw) != 6 {
			continue
		}
		var key [6]uint8
		copy(key[:], hw)
		desired[bpf.MACKey(key)] = p.ProjectID
	}
	return desired
}

// learnMACs inserts every desired MAC that is absent, ghosted, or whose
// tenant changed — userspace first, then kernel (docs/DESIGN.md §3.4).
// Learning a previously-unknown MAC is what lets the next scrape resolve
// its buffered flows. Returns (inserted, changed); an entry already live
// with the same tenant is left untouched.
func (r *Reconciler) learnMACs(desired map[uint64]string) (inserted, changed int) {
	for mac, projectID := range desired {
		cur, ok := r.meta.Lookup(mac)
		switch {
		case !ok:
			r.insertMAC(mac, projectID)
			inserted++
		case cur.ProjectID != projectID || !cur.DeleteAt.IsZero():
			// Tenant reassigned, or a ghost came back within its grace.
			r.insertMAC(mac, projectID)
			changed++
		}
	}
	return inserted, changed
}

// insertMAC writes one binding userspace-first then kernel (docs/DESIGN.md
// §3.4). The TenantMeta is replaced whole, never mutated (the immutable
// invariant). A kernel write failure is logged, not fatal — userspace
// already reflects the binding and the next pass retries the kernel side.
func (r *Reconciler) insertMAC(mac uint64, projectID string) {
	r.meta.Insert(mac, &metadata.TenantMeta{ProjectID: projectID})
	if err := r.macWriter.Update(mac, r.interner.Intern(projectID)); err != nil {
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
func (r *Reconciler) ghostGoneMACs(desired map[uint64]string, now time.Time) int {
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
		r.meta.MarkDelete(mac, now.Add(metadata.GhostGrace))
	}
	return len(gone)
}
