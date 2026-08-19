// Package kernelwriter pushes userspace metadata and trie entries into
// the kernel BPF maps. Shared by the cold-start path and the
// incremental-update path, so it lives outside both.
//
// BPF maps have no transactions, so a partial write cannot be rolled
// back. The contract is: log every per-entry failure, return the FIRST
// error, and let the caller treat it as boot-fatal — the next boot
// rebuilds the maps, so a half-written map does no harm. Both writers
// use ebpf.UpdateAny, which is what makes a re-asserted event idempotent.
//
// docs/architecture/boot-and-recovery.md#boot-sequence
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

// WriteMacTenantMap pushes every live (MAC, ProjectID) pair into
// macMap, interned to its u32 and packed with the entry's Amphora
// marker via [bpf.TenantValue]. Returns successful writes and the first
// error; later failures log but do not interrupt the walk, so the count
// stays meaningful.
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

	// Snapshot under the shard locks, then Update outside them: a BPF
	// map Update is a syscall, and holding a shard RLock across it would
	// block concurrent Inserts for a whole bulk push.
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

// WriteSubnetZoneTrie pushes entries into trieMap, interning each
// TenantID to its u32. Returns successful writes and the first error;
// later failures log but do not interrupt the walk.
//
// TenantID="" is valid — it is the global catchall / SHARED / INFRA
// rows, which intern to the reserved u32 0 that the C-side lookup_zone
// uses as its sentinel-fallback key.
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

// WriteAmphoraBaseIPs pushes the Amphora base-address set into
// amphoraMap, keyed by (interned LB-owner tenant, IPv4) via
// [bpf.AmphoraKeyForIP]. Presence in this map is what tells the
// classifier a flow is Octavia Segment 2 — load-balancer plumbing — as
// opposed to Segment 1, which must keep classifying by tenant
// (docs/architecture/octavia.md).
//
// Entries with an empty ProjectID are skipped: without a tenant there is
// no key to write, and the interner's zero sentinel would collide with
// the trie's global rows.
//
// Returns the count of successful writes and the first error, with the
// same partial-write semantics as [WriteMacTenantMap].
func WriteAmphoraBaseIPs(
	amphoraMap MapUpdater,
	entries []neutron.AmphoraBaseIP,
	interner *metadata.TenantInterner,
) (int, error) {
	if amphoraMap == nil {
		return 0, errors.New("kernelwriter: amphoraMap is nil")
	}
	if interner == nil {
		return 0, errors.New("kernelwriter: TenantInterner is nil")
	}
	var firstErr error
	var written int
	for _, e := range entries {
		if e.ProjectID == "" {
			continue
		}
		key := bpf.AmphoraKeyForIP(interner.Intern(e.ProjectID), e.Addr)
		val := uint8(1) // set semantics; only presence is read
		if err := amphoraMap.Update(&key, &val, ebpf.UpdateAny); err != nil {
			wrapped := fmt.Errorf("amphora_base_ip update tenant=%s ip=%s: %w", e.ProjectID, e.Addr, err)
			slog.Warn("amphora_base_ip write failed",
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
