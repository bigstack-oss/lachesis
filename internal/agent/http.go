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

	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/runtime"
)

// openHTTP wires the agent's HTTP surface: the Prometheus registry,
// the runtime manager's /debug routes, and the server bound to the
// configured listen address. Split from [New] so construction reads
// as data plane → metrics → HTTP, with the HTTP details here.
func (a *Agent) openHTTP(opts Options) error {
	reg, err := a.buildRegistry()
	if err != nil {
		return err
	}

	mgr := runtime.New(opts.ConfigPath, opts.Config, opts.Log)
	handler := buildHTTPHandler(reg, mgr)

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
// (e.g. a /healthz, a /reload, a /pprof under debug) attach to —
// rather than each one widening [New].
func buildHTTPHandler(reg *prometheus.Registry, mgr *runtime.Manager) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	mux.Handle("/debug/", mgr.DebugHandler())
	return mux
}

// Addr returns the address the HTTP server is bound to. Stable as
// soon as [New] returns; remains valid after Run starts and after it
// returns.
func (a *Agent) Addr() string {
	return a.listener.Addr().String()
}
