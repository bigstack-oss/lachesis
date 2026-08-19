// Package neutron is the OpenStack metadata path: Keystone auth, the
// Neutron API client, the trie builder, and the [Neutron] struct
// carrying one sync's outputs to the rest of the agent.
//
// The shape mirrors client-go's informer, with one deliberate
// deviation: retention is a separate [Neutron.Commit] rather than
// implicit in Sync, because the caller must push the new state into the
// kernel maps between the two. A sync timestamp must never describe
// state the kernel has not acknowledged.
//
// docs/architecture/trie-construction.md
package neutron

import (
	"errors"
	"sync/atomic"
	"time"

	"github.com/bigstack-oss/lachesis/internal/config"
	"github.com/bigstack-oss/lachesis/internal/tunables"
)

// Neutron carries the subsystem state for one agent process:
// credentials, the lazily-authenticated client, instruments, and the
// outputs of the last committed sync.
//
// Sync and Commit are single-goroutine; the read accessors are
// lock-free and safe alongside a running sync.
type Neutron struct {
	creds   Credentials
	metrics *Metrics
	// tun supplies the hot resolver knobs, read once per
	// [Neutron.Sync] so one trie build uses one consistent limit.
	// Never nil (the tunables required-dependency rule).
	tun *tunables.Store
	// info emits the identity info-metric families (lachesis_tenant_info,
	// lachesis_server_info) from the committed snapshot. Registered by
	// the agent alongside the metrics bundle. Never nil.
	info *InfoCollector

	// client is created by the first successful [Neutron.Sync] auth
	// and reused afterwards, so a transient list failure retried by
	// the caller does not re-authenticate. gophercloud refreshes the
	// token reactively (AllowReauth). Only the Sync goroutine touches
	// this field.
	client *Client

	// snapshot, trie, and anomalies retain the most recent committed
	// sync outputs for the /debug pages. Written by [Neutron.Commit]
	// via atomic pointer swap — whole-value replace, never in-place
	// mutation — so readers stay lock-free while a resync runs. nil
	// until the first Commit (Neutron disabled or not yet synced);
	// readers render the empty state.
	snapshot  atomic.Pointer[Snapshot]
	trie      atomic.Pointer[[]TrieEntry]
	anomalies atomic.Pointer[Anomalies]

	// lastSync is the unix-nanos timestamp of the most recent
	// [Neutron.Commit]. Read by the lachesis_neutron_sync_age_seconds
	// gauge at scrape time; zero means never-synced (the gauge
	// reports -1 so dashboards can spot the condition with `< 0`).
	lastSync atomic.Int64
}

// New constructs the subsystem. tun is required — the resolver reads
// its hop limit every sync. Credentials resolve eagerly so a malformed
// openrc fails construction instead of spinning in the caller's retry
// loop. With cfg.Enabled false, Sync must not be called; the accessors
// still report the never-synced state.
func New(cfg config.NeutronConfig, tun *tunables.Store) (*Neutron, error) {
	if tun == nil {
		return nil, errors.New("neutron: tunables store is required")
	}
	n := &Neutron{tun: tun}
	if cfg.Enabled {
		creds, err := FromConfig(cfg)
		if err != nil {
			return nil, err
		}
		n.creds = creds
	}
	n.metrics = NewMetrics(n.LastSyncTime)
	n.info = NewInfoCollector(n.Snapshot)
	return n, nil
}

// Metrics returns the subsystem's instrument bundle for the agent's
// registry to register. Never nil.
func (n *Neutron) Metrics() *Metrics { return n.metrics }

// InfoCollector returns the identity info-metric collector for the
// agent's registry to register alongside [Neutron.Metrics]. Never nil.
func (n *Neutron) InfoCollector() *InfoCollector { return n.info }

// Snapshot returns the most recently committed resource snapshot,
// or nil before the first [Neutron.Commit].
func (n *Neutron) Snapshot() *Snapshot { return n.snapshot.Load() }

// Trie returns the trie rows of the most recently committed sync,
// or nil before the first [Neutron.Commit].
func (n *Neutron) Trie() []TrieEntry {
	if p := n.trie.Load(); p != nil {
		return *p
	}
	return nil
}

// Anomalies returns the anomaly aggregate of the most recently
// committed sync, or nil before the first [Neutron.Commit].
func (n *Neutron) Anomalies() *Anomalies { return n.anomalies.Load() }

// LastSyncTime returns the timestamp of the most recent
// [Neutron.Commit], or the zero time.Time if none. Feeds the
// sync-age gauge via the provider wired in [New].
func (n *Neutron) LastSyncTime() time.Time {
	ns := n.lastSync.Load()
	if ns == 0 {
		return time.Time{}
	}
	return time.Unix(0, ns)
}

// EndpointURL returns the Neutron base URL gophercloud discovered
// from the Keystone catalog, or "" before the first successful auth.
// Log / metric attribution only. Like [Neutron.Sync], callers run on
// the sync goroutine.
func (n *Neutron) EndpointURL() string {
	if n.client == nil {
		return ""
	}
	return n.client.EndpointURL()
}
