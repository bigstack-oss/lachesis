// Package netlink discovers tap interfaces via RTM_NEWLINK / RTM_DELLINK
// and dynamically attaches the telemetry TC programs to each match,
// replacing the earlier static [config.BPFConfig.AttachInterface]
// single-interface attach.
//
// Cross-platform surface (this file and registry.go) is pure data
// and a [Subscriber] interface; the Linux implementation lives in
// subscriber_linux.go. The cross-platform Agent stores a Subscriber
// so darwin unit tests can wire a nil and Linux Bootstrap can wire
// the real one.
package netlink

import (
	"slices"
	"sort"
	"sync"
)

// Registry tracks which interfaces the subscriber has attached
// telemetry programs to. The subscriber consults it before attempting
// an attach (idempotent attach is cheap but skipping the netlink
// round-trip is cheaper) and on DELLINK to forget the entry.
//
// The zero value is not usable; call [NewRegistry].
type Registry struct {
	mu    sync.RWMutex
	names map[string]struct{}
}

// NewRegistry returns an empty Registry.
func NewRegistry() *Registry {
	return &Registry{names: make(map[string]struct{})}
}

// MarkAttached records iface as currently carrying our TC programs.
// Idempotent: a second call with the same name is a no-op.
func (r *Registry) MarkAttached(iface string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.names[iface] = struct{}{}
}

// IsAttached reports whether iface is in the registry.
func (r *Registry) IsAttached(iface string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.names[iface]
	return ok
}

// Forget removes iface from the registry, typically on a DELLINK
// event. Idempotent: forgetting an unknown name is a no-op.
func (r *Registry) Forget(iface string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.names, iface)
}

// Len returns the current number of attached interfaces, suitable
// for the cubecos_attached_interfaces gauge.
func (r *Registry) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.names)
}

// Snapshot returns the registry's contents in sorted order. The
// returned slice is owned by the caller; mutating it does not
// affect the registry.
func (r *Registry) Snapshot() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.names))
	for name := range r.names {
		out = append(out, name)
	}
	sort.Strings(out)
	return slices.Clip(out)
}
