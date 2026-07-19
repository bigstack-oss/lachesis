// Package neutron is the OpenStack metadata path. It owns Keystone
// v3 authentication (via gophercloud), the Neutron v2.0 API client,
// the trie builder that turns a resource snapshot into kernel LPM
// rows, and the [Neutron] struct that carries one sync's outputs for
// the rest of the agent. See docs/architecture/trie-construction.md.
//
// # Composition
//
// The shape mirrors client-go's informer: [Neutron.Sync] is the list
// pass (relist on every call; the future Kafka updater is the watch
// half), the atomic fields inside [Neutron] are the local store, and
// the read accessors are the listers the /debug pages consume. One
// deliberate deviation from client-go: retention is a separate
// [Neutron.Commit] call rather than implicit in Sync, because the
// caller must push the new state into the kernel maps between the
// two — a fresh sync timestamp must never describe state the kernel
// has not acknowledged.
//
// # File layout
//
// One [Neutron] struct, method files by functionality: construction
// and accessors here, the Sync/Commit pair in sync.go. The API
// client lives in client.go (auth) and list.go (list adapters), the
// credential sources in credentials.go, the builder in trie.go with
// its static-route resolver in resolve.go, port classification in
// deviceowner.go, snapshot health checks in anomalies.go, read-side
// lookup helpers in lookup.go, and the instrument bundle in
// metrics.go. Pure-data holders and package vocabulary live in
// schema.go / types.go.
package neutron

import (
	"sync/atomic"
	"time"

	"github.com/bigstack-oss/lachesis/internal/config"
)

// Neutron carries the full Neutron subsystem state for one agent
// process: the resolved credentials, the lazily-authenticated API
// client, the subsystem's Prometheus instruments, and the retained
// outputs of the most recent committed sync (snapshot, trie rows,
// anomalies, sync time).
//
// Construct with [New]. [Neutron.Sync] and [Neutron.Commit] are
// single-goroutine — the agent serialises cold-start and the future
// Kafka resync on one worker. The read accessors are lock-free and
// safe to call concurrently with a running sync.
type Neutron struct {
	creds   Credentials
	metrics *Metrics
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

// New constructs the subsystem from its config. Credentials are
// resolved eagerly (including reading a credentials_file) so a
// malformed openrc fails construction instead of spinning inside the
// caller's sync retry loop. When cfg.Enabled is false the credentials
// stay zero and [Neutron.Sync] must not be called; the accessors and
// the metrics bundle still work, reporting the never-synced state.
func New(cfg config.NeutronConfig) (*Neutron, error) {
	n := &Neutron{}
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
