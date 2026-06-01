package metadata

import "sync"

// TenantInterner assigns and remembers stable u32 identifiers for
// Keystone project UUIDs. The kernel `mac_tenant_map` and
// `subnet_zone_trie` are both keyed on `__u32 tenant_id`; the
// interner is the bridge from the userspace ProjectID UUID (the
// Neutron-authoritative identity that ends up as the `tenant_id`
// Prometheus label) to the compact integer the kernel stores.
//
// # Restart safety
//
// The mapping is in-memory only and rebuilt on every agent boot.
// docs/DESIGN.md §9 specifies that the kernel maps are freshly
// loaded at every boot, so any prior u32 assignment would be
// replaced anyway. This is correctness-safe because no u32 leaks
// outside the kernel maps — [bpf.FlowKey] and [state.Record] are
// both u32-free by invariant (see those types' doc comments), so
// WAL-restored GlobalState merges cleanly with post-restart flows
// regardless of what u32 the interner happens to assign this boot.
//
// # Concurrency
//
// All operations take a single mutex. Insertion volume is bounded
// by the tenant count (hundreds to low thousands), so a sharded
// approach is not warranted. The hot-path Prometheus scrape does
// not consult the interner — it reads ProjectID strings directly
// from [ShardedMetadataMap] — so contention only matters during
// cold start and Kafka catch-up.
type TenantInterner struct {
	mu      sync.Mutex
	nextID  uint32
	forward map[string]uint32
	reverse map[uint32]string
}

// NewTenantInterner returns an empty interner. The first [Intern]
// call against a non-empty ProjectID will return 1.
func NewTenantInterner() *TenantInterner {
	return &TenantInterner{
		nextID:  1,
		forward: make(map[string]uint32),
		reverse: make(map[uint32]string),
	}
}

// Intern returns the u32 ID for projectID, assigning a new
// monotonic ID on first sight. An empty projectID always returns
// [TenantIDUnset] without mutating state — useful for "unbound" or
// "admin-owned" rows where no project assignment is meaningful.
func (t *TenantInterner) Intern(projectID string) uint32 {
	if projectID == "" {
		return TenantIDUnset
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if id, ok := t.forward[projectID]; ok {
		return id
	}
	id := t.nextID
	t.nextID++
	t.forward[projectID] = id
	t.reverse[id] = projectID
	return id
}

// Lookup returns the u32 for projectID without assigning a new one.
// Returns (TenantIDUnset, false) for unknown or empty input.
func (t *TenantInterner) Lookup(projectID string) (uint32, bool) {
	if projectID == "" {
		return TenantIDUnset, false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	id, ok := t.forward[projectID]
	return id, ok
}

// Reverse returns the ProjectID for an interned id. Returns
// ("", false) for [TenantIDUnset] or any never-assigned id. Used
// by `/debug` endpoints that want a human-readable label.
func (t *TenantInterner) Reverse(id uint32) (string, bool) {
	if id == TenantIDUnset {
		return "", false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	p, ok := t.reverse[id]
	return p, ok
}

// Len returns the number of interned project IDs.
func (t *TenantInterner) Len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.forward)
}
