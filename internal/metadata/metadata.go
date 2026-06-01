// Package metadata is the userspace mirror of the kernel
// `mac_tenant_map`. It maps a VM MAC to a [*TenantMeta] carrying the
// richer attributes the kernel cannot store (project UUID, VM name,
// LB-Amphora flag, deletion grace timestamp). See docs/DESIGN.md
// §3.2.
//
// # Invariants
//
// (1) Stored [TenantMeta] values are immutable. Multiple MACs may
// share the same `*TenantMeta` — pointer-replace on update, never
// in-place mutation. A scrape that captures the pointer may keep
// using it after a concurrent update; the captured fields stay
// consistent for the lifetime of that scrape.
//
// (2) [ShardedMetadataMap] is a strict superset of the kernel
// `mac_tenant_map`. Insertions go userspace-first, then kernel.
// Deletions go kernel-first (after the 60 s Lingering Ghost in
// docs/DESIGN.md §3.3), then userspace. The ordering is the caller's
// responsibility; this package only enforces the data-structure
// invariants and provides the [MarkDelete] hook the GC drives.
//
// # Sharding
//
// 64 shards × `sync.RWMutex`, indexed by `mac & 63`. The shard count
// is fixed and load-bearing: it bounds writer contention while
// keeping every shard's working set close to one L1 cacheline of
// metadata at typical scales. The MAC encoding (big-endian into the
// low 48 bits of a u64) matches the kernel's `mac_to_u64`; both
// sides agreeing is what makes cross-language map lookups consistent.
package metadata

import (
	"sync"
	"time"
)

// ShardedMetadataMap is the userspace MAC→[*TenantMeta] store. Safe
// for concurrent use; see package doc for the immutability and
// superset-of-mac_tenant_map invariants.
type ShardedMetadataMap struct {
	shards [numShards]shard
}

type shard struct {
	mu sync.RWMutex
	m  map[uint64]*TenantMeta
}

// New returns an empty [ShardedMetadataMap] with all shards
// pre-allocated.
func New() *ShardedMetadataMap {
	s := &ShardedMetadataMap{}
	for i := range s.shards {
		s.shards[i].m = make(map[uint64]*TenantMeta)
	}
	return s
}

func (s *ShardedMetadataMap) shardFor(mac uint64) *shard {
	return &s.shards[mac&(numShards-1)]
}

// Lookup returns the metadata pointer for mac, or (nil, false) if
// unknown. The returned pointer is safe to retain past the call: the
// immutability invariant guarantees its fields will not change.
func (s *ShardedMetadataMap) Lookup(mac uint64) (*TenantMeta, bool) {
	sh := s.shardFor(mac)
	sh.mu.RLock()
	v, ok := sh.m[mac]
	sh.mu.RUnlock()
	return v, ok
}

// Insert stores meta under mac, replacing any prior pointer. Callers
// must treat meta as immutable from the moment Insert returns; other
// goroutines may already hold the prior pointer and will continue to
// read its (frozen) fields.
func (s *ShardedMetadataMap) Insert(mac uint64, meta *TenantMeta) {
	sh := s.shardFor(mac)
	sh.mu.Lock()
	sh.m[mac] = meta
	sh.mu.Unlock()
}

// Delete unconditionally removes mac. Intended for the GC after the
// Lingering Ghost window has expired and the kernel `mac_tenant_map`
// entry has already been removed (docs/DESIGN.md §3.4). Most call
// sites that observe a Neutron deletion event should call
// [ShardedMetadataMap.MarkDelete] instead.
func (s *ShardedMetadataMap) Delete(mac uint64) {
	sh := s.shardFor(mac)
	sh.mu.Lock()
	delete(sh.m, mac)
	sh.mu.Unlock()
}

// MarkDelete sets `DeleteAt = at` on the entry for mac by replacing
// its [*TenantMeta] pointer with a copy whose DeleteAt field is
// updated. Returns false if mac is unknown. The kernel
// `mac_tenant_map` entry is NOT touched; that deletion is the GC's
// responsibility once the grace window passes.
func (s *ShardedMetadataMap) MarkDelete(mac uint64, at time.Time) bool {
	sh := s.shardFor(mac)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	prior, ok := sh.m[mac]
	if !ok {
		return false
	}
	next := *prior
	next.DeleteAt = at
	sh.m[mac] = &next
	return true
}

// Len returns the total number of entries across every shard. It
// acquires each shard's read lock in turn, so it is O(numShards) in
// lock operations and not intended for hot-path use.
func (s *ShardedMetadataMap) Len() int {
	n := 0
	for i := range s.shards {
		s.shards[i].mu.RLock()
		n += len(s.shards[i].m)
		s.shards[i].mu.RUnlock()
	}
	return n
}

// Range calls f for every live (MAC, *TenantMeta) entry. The walk
// is shard-by-shard under a shared (read) lock per shard, so f must
// not call any method on s that takes a write lock on the same
// shard — that deadlocks. f returning false stops iteration early.
//
// Snapshot semantics are weak: entries in shards iterated after the
// current one may already reflect concurrent inserts / deletes
// completed during the walk. Callers that need a fully consistent
// view should serialise externally.
func (s *ShardedMetadataMap) Range(f func(mac uint64, meta *TenantMeta) bool) {
	for i := range s.shards {
		s.shards[i].mu.RLock()
		stop := false
		for mac, meta := range s.shards[i].m {
			if !f(mac, meta) {
				stop = true
				break
			}
		}
		s.shards[i].mu.RUnlock()
		if stop {
			return
		}
	}
}
