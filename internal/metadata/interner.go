package metadata

import "sync"

// TenantInterner bridges the userspace project UUID to the compact u32
// the kernel maps key on.
//
// The mapping is in-memory and rebuilt every boot, which is safe only
// because no u32 leaks outside the kernel maps — [bpf.FlowKey] and
// [state.Record] are u32-free by invariant, so WAL-restored state
// merges cleanly whatever this boot assigns.
//
// One mutex: volume is bounded by tenant count, and the scrape path
// reads ProjectID strings directly rather than consulting it.
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
