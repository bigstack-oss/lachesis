// delta.go holds the incremental trie writer used by the runtime
// metadata-update paths (the periodic Neutron reconcile and the Kafka
// consumer). Where [WriteSubnetZoneTrie] rewrites the whole map at
// cold-start, [ApplyTrieDelta] pushes only the rows that changed
// between two snapshots — and pushes them in the order docs/DESIGN.md
// §5.7 requires.

package kernelwriter

import (
	"errors"
	"fmt"
	"log/slog"
	"net/netip"

	"github.com/cilium/ebpf"

	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/bpf"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/metadata"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/neutron"
)

// MapUpdateDeleter is the subset of [*ebpf.Map] the incremental trie
// writer depends on: [WriteSubnetZoneTrie]'s upsert plus per-entry
// Delete. Kept separate from [MapUpdater] so the cold-start writers
// declare only the method they use (the consumer-defined-interface
// rule); *ebpf.Map satisfies both.
type MapUpdateDeleter interface {
	MapUpdater
	Delete(key any) error
}

// TrieDelta counts what one [ApplyTrieDelta] pass did: rows whose key
// was absent before (Added), rows whose key existed with a different
// zone (Changed), and rows present before but gone now (Removed). Rows
// that are identical in both snapshots are left untouched and counted
// nowhere — re-asserting an unchanged row would be a wasted syscall.
type TrieDelta struct {
	Added   int
	Changed int
	Removed int
}

// trieRowKey is the identity of one kernel trie row: the interned
// tenant ID plus the IPv4 prefix. It mirrors what [bpf.LpmKeyForPrefix]
// keys on, but stays comparable (netip.Prefix is comparable) so it can
// be a Go map key for the diff. Two [neutron.TrieEntry] values address
// the same kernel row iff their trieRowKey matches; the row's value is
// the zone.
type trieRowKey struct {
	tid    uint32
	prefix netip.Prefix
}

// ApplyTrieDelta brings trieMap from the oldEntries state to the
// newEntries state with the minimum set of kernel writes, in the
// strict order docs/DESIGN.md §5.7 mandates: **all upserts first, then
// all deletes.** Deleting an obsolete row before its replacement is in
// place would briefly leave the destination CIDR unmatched, and a
// packet that falls through to the catchall during that window is
// permanently miskeyed because dst_zone is baked into the kernel
// flow_key. Insert-first guarantees a valid longest-prefix match exists
// at every instant.
//
// Identity is (interned tenant_id, prefix); the value compared is the
// zone. Added/Changed rows are upserted with ebpf.UpdateAny; rows that
// disappeared are deleted; identical rows are skipped.
//
// Tenant IDs are resolved through [metadata.TenantInterner.Intern] on
// both sides — allocating a u32 for a genuinely new tenant, returning
// the existing one for a tenant a prior pass already wrote (idempotent),
// and mapping the sentinel "" tenant to TenantIDUnset.
//
// # Failure semantics
//
// Each per-row failure is logged; the first is returned. If any upsert
// fails, the delete phase is skipped entirely — deleting an old row
// whose replacement may not have landed is exactly the miskey window
// §5.7 warns about, and a stale-but-present row is harmless under LPM
// longest-match. The next reconcile (or Kafka event) retries. The
// returned [TrieDelta] reflects the writes that actually succeeded.
func ApplyTrieDelta(
	trieMap MapUpdateDeleter,
	oldEntries, newEntries []neutron.TrieEntry,
	interner *metadata.TenantInterner,
) (TrieDelta, error) {
	if trieMap == nil {
		return TrieDelta{}, errors.New("kernelwriter: trieMap is nil")
	}
	if interner == nil {
		return TrieDelta{}, errors.New("kernelwriter: TenantInterner is nil")
	}

	// Index the desired end state by row identity. Intern here so new
	// tenants get a u32, matching WriteSubnetZoneTrie.
	newRows := make(map[trieRowKey]uint8, len(newEntries))
	for i := range newEntries {
		e := &newEntries[i]
		newRows[trieRowKey{interner.Intern(e.TenantID), e.Prefix}] = uint8(e.Zone)
	}

	// Index the prior state. Intern (idempotent here): an old row was
	// written by a prior pass that already interned its tenant, so this
	// returns the same u32 without allocating — and it maps the sentinel
	// "" tenant to TenantIDUnset, which Lookup would instead report as a
	// miss.
	oldRows := make(map[trieRowKey]uint8, len(oldEntries))
	for i := range oldEntries {
		e := &oldEntries[i]
		oldRows[trieRowKey{interner.Intern(e.TenantID), e.Prefix}] = uint8(e.Zone)
	}

	var firstErr error
	var delta TrieDelta

	// Phase 1: upsert added and changed rows. Skip identical ones.
	for rk, zone := range newRows {
		prev, existed := oldRows[rk]
		if existed && prev == zone {
			continue
		}
		key := bpf.LpmKeyForPrefix(rk.tid, rk.prefix)
		val := zone
		if err := trieMap.Update(&key, &val, ebpf.UpdateAny); err != nil {
			wrapped := fmt.Errorf("subnet_zone_trie upsert tenant_id=%d prefix=%s: %w", rk.tid, rk.prefix, err)
			slog.Warn("subnet_zone_trie delta upsert failed",
				"component", componentKernelWriter, "err", wrapped)
			if firstErr == nil {
				firstErr = wrapped
			}
			continue
		}
		if existed {
			delta.Changed++
		} else {
			delta.Added++
		}
	}

	// An upsert failure means a replacement row may be missing; deleting
	// now could open the §5.7 miskey window. Keep the stale rows (LPM
	// longest-match tolerates them) and let the next pass retry.
	if firstErr != nil {
		return delta, firstErr
	}

	// Phase 2: delete rows that no longer exist.
	for rk := range oldRows {
		if _, kept := newRows[rk]; kept {
			continue
		}
		key := bpf.LpmKeyForPrefix(rk.tid, rk.prefix)
		if err := trieMap.Delete(&key); err != nil {
			wrapped := fmt.Errorf("subnet_zone_trie delete tenant_id=%d prefix=%s: %w", rk.tid, rk.prefix, err)
			slog.Warn("subnet_zone_trie delta delete failed",
				"component", componentKernelWriter, "err", wrapped)
			if firstErr == nil {
				firstErr = wrapped
			}
			continue
		}
		delta.Removed++
	}

	return delta, firstErr
}
