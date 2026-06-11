// http.go owns the agent's HTTP surface: the Prometheus registry
// wiring, the route table, the listener/server assembly, and Addr.
// The Agent type and its construction live in agent.go.

package agent

import (
	"fmt"
	"net"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/debug"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/neutron"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/runtime"
)

// openHTTP wires the agent's HTTP surface: the Prometheus registry,
// the /debug pages, and the server bound to the configured listen
// address. Split from [New] so construction reads as data plane →
// metrics → HTTP, with the HTTP details here.
func (a *Agent) openHTTP(opts Options) error {
	reg, err := a.buildRegistry()
	if err != nil {
		return err
	}

	mgr := runtime.New(opts.ConfigPath, opts.Config, opts.Log)
	dbg := debug.New(debug.Options{
		Snapshot:  a.neutronSnapshot.Load,
		Trie:      a.trieEntriesView,
		Anomalies: a.anomalies.Load,
		LastSync:  a.lastNeutronSyncTime,
		MACLookup: a.meta.Lookup,
		Fallback:  mgr.DebugHandler(),
	})
	handler := buildHTTPHandler(reg, dbg.Handler())

	ln, err := net.Listen("tcp", opts.Config.HTTP.Listen)
	if err != nil {
		return fmt.Errorf("agent: listen %s: %w", opts.Config.HTTP.Listen, err)
	}

	a.runtime = mgr
	a.listener = ln
	a.server = &http.Server{Handler: handler, ReadHeaderTimeout: httpReadHeaderTimeout}
	return nil
}

// buildRegistry creates a fresh Prometheus registry and binds the
// agent's custom Collector plus every subsystem instrument bundle to
// it, so /metrics is the single endpoint operators scrape — billing
// and subsystem health on one wire.
func (a *Agent) buildRegistry() (*prometheus.Registry, error) {
	reg := prometheus.NewRegistry()
	if err := reg.Register(a.collector); err != nil {
		return nil, fmt.Errorf("agent: register collector: %w", err)
	}
	for _, r := range a.mx.registrations() {
		for _, c := range r.collectors {
			if err := reg.Register(c); err != nil {
				return nil, fmt.Errorf("agent: register %s metric: %w", r.label, err)
			}
		}
	}
	return reg, nil
}

// buildHTTPHandler returns the mux the HTTP server will serve.
// Centralising the route table here is the seam future subsystems
// (e.g. a /healthz, a /reload) attach to — rather than each one
// widening [New]. The debug handler owns the whole /debug subtree
// (pages, pprof, and the runtime manager's config/log-level routes
// via its fallback), so it mounts both the exact "/debug" index
// path and the "/debug/" subtree.
func buildHTTPHandler(reg *prometheus.Registry, dbg http.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	mux.Handle("/debug", dbg)
	mux.Handle("/debug/", dbg)
	return mux
}

// Addr returns the address the HTTP server is bound to. Stable as
// soon as [New] returns; remains valid after Run starts and after it
// returns.
func (a *Agent) Addr() string {
	return a.listener.Addr().String()
}

// trieEntriesView adapts the agent's atomic trie-entries pointer to
// the value-slice accessor the debug server takes. nil before the
// first successful Neutron sync.
func (a *Agent) trieEntriesView() []neutron.TrieEntry {
	if p := a.trieEntries.Load(); p != nil {
		return *p
	}
	return nil
}
