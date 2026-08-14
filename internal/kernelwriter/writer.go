// Package kernelwriter pushes userspace metadata and trie entries
// into the kernel BPF maps loaded from internal/bpf. It is shared
// between the cold-start path (agent Bootstrap) and the
// incremental-update path (Kafka consumer), so it lives outside
// both.
//
// # Failure semantics
//
// The kernel maps do not support transactions; partial writes
// cannot be rolled back atomically. The package's contract is:
// log every per-entry failure (so an operator can see which row
// went wrong) and return the FIRST error encountered. The caller
// is expected to treat any non-nil error as a boot-fatal condition
// — the next agent boot rebuilds the maps from scratch
// (docs/architecture/boot-and-recovery.md#boot-sequence), so a partially-written map from a failed boot does no harm.
//
// # Update mode
//
// Both writers use `ebpf.UpdateAny` (insert-or-overwrite). At cold
// start the maps are empty so the choice is moot; for incremental
// updates UpdateAny is correct — a Kafka event re-asserts the
// current state and a stale entry should be overwritten in place.
package kernelwriter

import (
	"errors"
	"fmt"
	"log/slog"

	"github.com/cilium/ebpf"

	"github.com/bigstack-oss/lachesis/internal/bpf"
	"github.com/bigstack-oss/lachesis/internal/metadata"
	"github.com/bigstack-oss/lachesis/internal/neutron"
)

// MapUpdater is the subset of [*ebpf.Map] the writers depend on.
// Defined as an interface so unit tests can mock without needing a
// real kernel BPF environment.
type MapUpdater interface {
	Update(key, value any, flags ebpf.MapUpdateFlags) error
}

// WriteMacTenantMap pushes every live (MAC, ProjectID) pair in snap
// into macMap, mapped through interner to its u32 tenant_id and packed
// with the entry's Amphora marker via [bpf.TenantValue]. Entries with
// empty ProjectID are skipped (no kernel binding to make).
//
// Returns the count of successful writes and the first error
// encountered. Subsequent failures within the same call are logged
// at warn-level but do not interrupt the walk — the caller wants
// to know how many succeeded.
func WriteMacTenantMap(
	macMap MapUpdater,
	snap *metadata.ShardedMetadataMap,
	interner *metadata.TenantInterner,
) (int, error) {
	if macMap == nil {
		return 0, errors.New("kernelwriter: macMap is nil")
	}
	if snap == nil {
		return 0, errors.New("kernelwriter: ShardedMetadataMap is nil")
	}
	if interner == nil {
		return 0, errors.New("kernelwriter: TenantInterner is nil")
	}

	// Snapshot the (mac, tenant_id) pairs under the shard locks first,
	// then issue the kernel Updates outside any lock. A BPF map Update
	// is a syscall (IO), and the locking guideline forbids holding a
	// mutex across IO: doing the Update inside snap.Range would hold the
	// shard RLock for the whole syscall and block a concurrent
	// Kafka-driven Insert/MarkDelete on that shard for the duration of a
	// bulk push. Interning is a cheap userspace map op, so it stays in
	// the snapshot pass. This runs at cold-start / on Kafka updates, not
	// on the scrape or packet hot path, so the snapshot slice is fine.
	type macTenant struct {
		mac uint64
		tid uint32
	}
	var pairs []macTenant
	snap.Range(func(mac uint64, meta *metadata.TenantMeta) bool {
		if meta.ProjectID == "" {
			return true
		}
		pairs = append(pairs, macTenant{mac, bpf.TenantValue(interner.Intern(meta.ProjectID), meta.IsAmphora)})
		return true
	})

	var firstErr error
	var written int
	for _, p := range pairs {
		k, v := p.mac, p.tid
		if err := macMap.Update(&k, &v, ebpf.UpdateAny); err != nil {
			wrapped := fmt.Errorf("mac_tenant_map update mac=%012x tenant_id=%d: %w", p.mac, p.tid, err)
			slog.Warn("mac_tenant_map write failed",
				"component", componentKernelWriter, "err", wrapped)
			if firstErr == nil {
				firstErr = wrapped
			}
			continue
		}
		written++
	}
	return written, firstErr
}

// WriteSubnetZoneTrie pushes every entry in entries into trieMap.
// Each entry's TenantID (a Keystone project UUID) is interned to
// its u32 via interner; the resulting LpmKey is written with the
// entry's zone code as the value.
//
// Returns the count of successful writes and the first error
// encountered. As with WriteMacTenantMap, subsequent failures log
// but do not interrupt the walk.
//
// # Sentinel rows
//
// Entries with TenantID="" are valid: they represent the global
// catchall / SHARED / INFRA rows that [neutron.BuildTrie] emits
// once per snapshot under the trie-dedup model. [TenantInterner.Intern]
// already maps the empty string to [metadata.TenantIDUnset] (the
// reserved u32 0), so the writer needs no special case — the LPM
// key lands at `tenant_id=0`, which the C-side `lookup_zone` uses
// as the sentinel-fallback key after a per-tenant lookup miss.
func WriteSubnetZoneTrie(
	trieMap MapUpdater,
	entries []neutron.TrieEntry,
	interner *metadata.TenantInterner,
) (int, error) {
	if trieMap == nil {
		return 0, errors.New("kernelwriter: trieMap is nil")
	}
	if interner == nil {
		return 0, errors.New("kernelwriter: TenantInterner is nil")
	}
	var firstErr error
	var written int
	for i := range entries {
		e := &entries[i]
		tid := interner.Intern(e.TenantID)
		key := bpf.LpmKeyForPrefix(tid, e.Prefix)
		zone := uint8(e.Zone)
		if err := trieMap.Update(&key, &zone, ebpf.UpdateAny); err != nil {
			wrapped := fmt.Errorf("subnet_zone_trie update tenant_id=%d prefix=%s: %w", tid, e.Prefix, err)
			slog.Warn("subnet_zone_trie write failed",
				"component", componentKernelWriter, "err", wrapped)
			if firstErr == nil {
				firstErr = wrapped
			}
			continue
		}
		written++
	}
	return written, firstErr
}
