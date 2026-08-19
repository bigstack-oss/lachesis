// sync.go owns the [Neutron.Sync] / [Neutron.Commit] pair: the full
// list-and-rebuild pass against the OpenStack APIs, and the atomic
// retention of its outputs once the caller has pushed them into the
// kernel. The Neutron struct and its read accessors live in
// neutron.go.

package neutron

import (
	"context"
	"fmt"
	"log/slog"
	"time"
)

// Sync runs one full list-and-rebuild pass, recording per-endpoint
// failures before returning. It retains NOTHING: the result becomes
// visible only when the caller passes it to [Neutron.Commit]. That
// split exists so the kernel maps can acknowledge the new state in
// between — a sync timestamp must never describe state the kernel has
// not seen.
//
// Single-shot; retry policy belongs to the caller.
//
// docs/architecture/boot-and-recovery.md#boot-sequence
func (n *Neutron) Sync(ctx context.Context) (SyncResult, error) {
	if n.client == nil {
		c, err := NewClient(ctx, n.creds)
		if err != nil {
			n.metrics.RecordAPIError(endpointKeystone, err)
			return SyncResult{}, fmt.Errorf("keystone auth: %w", err)
		}
		n.client = c
	}
	snap, err := n.fetchAll(ctx)
	if err != nil {
		return SyncResult{}, err
	}
	return n.resultFor(snap), nil
}

// resultFor turns a fetched snapshot into the sync outputs: it is the
// half of [Neutron.Sync] that needs no API client, so a test can drive
// the real trie-build path — including the operator's hop limit coming
// off the tunables store — without a live cluster.
//
// One Get per build: every route resolves against the same hop limit
// even if a SIGHUP lands while the trie is building.
func (n *Neutron) resultFor(snap Snapshot) SyncResult {
	entries, ambiguities, cycles := buildTrie(snap, n.metrics, n.tun.Get().MaxStaticRouteHops)
	return SyncResult{
		Snapshot:    snap,
		Entries:     entries,
		Ambiguities: ambiguities,
		Cycles:      cycles,
		Anomalies:   DetectAnomalies(snap, entries, cycles, ambiguities),
	}
}

// fetchAll issues the list calls in sequence and records
// per-endpoint API errors. The endpoint label is the resource name,
// which corresponds 1:1 to the Neutron URL path. The Keystone
// project list rides along so downstream consumers (/debug pages,
// log enrichment) can resolve project IDs to names.
func (n *Neutron) fetchAll(ctx context.Context) (Snapshot, error) {
	var s Snapshot
	var err error
	if s.Networks, err = n.client.ListNetworks(ctx); err != nil {
		n.metrics.RecordAPIError(endpointNetworks, err)
		return s, fmt.Errorf("list networks: %w", err)
	}
	if s.Subnets, err = n.client.ListSubnets(ctx); err != nil {
		n.metrics.RecordAPIError(endpointSubnets, err)
		return s, fmt.Errorf("list subnets: %w", err)
	}
	if s.Ports, err = n.client.ListPorts(ctx); err != nil {
		n.metrics.RecordAPIError(endpointPorts, err)
		return s, fmt.Errorf("list ports: %w", err)
	}
	if s.Routers, err = n.client.ListRouters(ctx); err != nil {
		n.metrics.RecordAPIError(endpointRouters, err)
		return s, fmt.Errorf("list routers: %w", err)
	}
	if s.FloatingIPs, err = n.client.ListFloatingIPs(ctx); err != nil {
		n.metrics.RecordAPIError(endpointFloatingIPs, err)
		return s, fmt.Errorf("list floatingips: %w", err)
	}
	if s.Projects, err = n.client.ListProjects(ctx); err != nil {
		n.metrics.RecordAPIError(endpointProjects, err)
		return s, fmt.Errorf("list projects: %w", err)
	}
	// The Nova server list rides along for the optional
	// lachesis_server_info family. Unlike the lists above it is
	// non-fatal: a fetch failure records the API error, leaves
	// Servers empty (info series absent), and lets the sync complete
	// so the billing path is unaffected.
	//
	// Info metrics: docs/architecture/metrics.md
	if s.Servers, err = n.client.ListServers(ctx); err != nil {
		n.metrics.RecordAPIError(endpointServers, err)
		slog.Warn("list servers failed; lachesis_server_info absent until the next sync succeeds",
			"component", componentNeutron, "err", err)
		s.Servers = nil
	}
	// The Octavia lists ride along on the same non-fatal terms: they
	// feed Amphora re-attribution (docs/architecture/octavia.md), which
	// is additive. A missing endpoint, an admin-only policy rejection on
	// the amphora list, or a transient Octavia outage leaves the lists
	// empty and every Amphora port keeps the service project's
	// attribution — wrong, but self-correcting on the next sync, and far
	// better than refusing to bill anything at all.
	if s.LoadBalancers, err = n.client.ListLoadBalancers(ctx); err != nil {
		n.metrics.RecordAPIError(endpointLoadBalancers, err)
		slog.Warn("list loadbalancers failed; Amphora traffic bills the service project until the next sync succeeds",
			"component", componentNeutron, "err", err)
		s.LoadBalancers = nil
	}
	if s.Amphorae, err = n.client.ListAmphorae(ctx); err != nil {
		n.metrics.RecordAPIError(endpointAmphorae, err)
		slog.Warn("list amphorae failed; Amphora traffic bills the service project until the next sync succeeds",
			"component", componentNeutron, "err", err)
		s.Amphorae = nil
	}
	// Servers and the Octavia lists are non-fatal: return nil regardless
	// of their errors above, so neither a Nova nor an Octavia failure
	// aborts the sync.
	return s, nil
}

// Commit publishes result to the read accessors, replaces the
// anomaly gauge counts, and marks `at` as the most recent successful
// sync. Call only after the kernel maps have acknowledged result —
// see [Neutron.Sync] for why retention is split out.
func (n *Neutron) Commit(result SyncResult, at time.Time) {
	n.metrics.SetAnomalies(result.Anomalies)
	// Retain before marking the sync time, so a fresh timestamp
	// never points at stale (or nil) debug state.
	n.snapshot.Store(&result.Snapshot)
	n.trie.Store(&result.Entries)
	n.anomalies.Store(&result.Anomalies)
	n.lastSync.Store(at.UnixNano())
}
