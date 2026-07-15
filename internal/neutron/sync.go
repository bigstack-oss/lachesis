// sync.go owns the [Neutron.Sync] / [Neutron.Commit] pair: the full
// list-and-rebuild pass against the OpenStack APIs, and the atomic
// retention of its outputs once the caller has pushed them into the
// kernel. The Neutron struct and its read accessors live in
// neutron.go.

package neutron

import (
	"context"
	"fmt"
	"time"
)

// Sync runs one full list-and-rebuild pass: authenticate against
// Keystone (first call only; the client is cached so a transient
// fetch failure does not re-auth), drain the six list endpoints,
// build the trie, and detect anomalies. Per-endpoint failures are
// recorded on lachesis_neutron_api_errors_total before returning.
//
// Sync retains nothing — the returned [SyncResult] becomes visible
// to the read accessors only when the caller hands it to
// [Neutron.Commit]. The split exists because the kernel maps must
// acknowledge the new state between the two calls (docs/DESIGN.md
// §9 step 3): a fresh sync timestamp must never describe state the
// kernel has not seen.
//
// Sync is single-shot; retry/backoff policy belongs to the caller
// (the agent's cold-start loop, which classifies retryability).
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
	entries, ambiguities, cycles := buildTrie(snap, n.metrics)
	return SyncResult{
		Snapshot:    snap,
		Entries:     entries,
		Ambiguities: ambiguities,
		Cycles:      cycles,
		Anomalies:   DetectAnomalies(snap, entries, cycles, ambiguities),
	}, nil
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
