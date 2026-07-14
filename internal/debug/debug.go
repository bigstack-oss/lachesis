// Package debug serves the agent's operator-facing /debug surface:
// an HTML index with sync health and anomaly counts, detail pages
// for attribution state, and the stdlib pprof handlers. Every HTML
// page returns its exact view model as JSON under `?format=json`,
// so the same data is one curl away from a script.
//
// The package owns no state: [New] takes read-only accessor funcs
// over the snapshot/trie/anomalies the agent retains via atomic
// pointer swap, plus a fallback handler for the /debug routes other
// subsystems own (runtime.Manager's /debug/config and
// /debug/log-level). The agent mounts [Server.Handler] under /debug
// in its route table.
//
// The endpoints are intentionally not authenticated; bind the HTTP
// server to localhost or behind a reverse proxy if the host is
// untrusted.
package debug

import (
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/http/pprof"
	"time"

	"github.com/bigstack-oss/lachesis/internal/metadata"
	"github.com/bigstack-oss/lachesis/internal/neutron"
)

//go:embed templates/*.html
var templates embed.FS

// Options carries the read-only views [New] binds the server to.
// Every accessor may be nil — the corresponding page section then
// renders its empty state ("never synced", zero counts) — so tests
// and a Neutron-disabled agent need no stubs.
type Options struct {
	// Snapshot returns the most recent Neutron snapshot, or nil
	// before the first successful sync.
	Snapshot func() *neutron.Snapshot
	// Trie returns the most recent LPM trie rows, or nil.
	Trie func() []neutron.TrieEntry
	// Anomalies returns the most recent detection pass, or nil.
	Anomalies func() *neutron.Anomalies
	// LastSync returns the most recent successful sync time; the
	// zero time means never-synced.
	LastSync func() time.Time
	// MACLookup resolves a kernel mac_tenant_map key (bpf.MACKey
	// form) against the userspace mirror. nil renders the MAC
	// section as not-found.
	MACLookup func(mac uint64) (*metadata.TenantMeta, bool)
	// Fallback handles /debug routes this package does not own
	// (runtime.Manager's /debug/config, /debug/log-level). nil
	// means unknown /debug paths 404.
	Fallback http.Handler
}

// Server renders the /debug pages. Construct with [New]; mount
// [Server.Handler] on the agent's mux.
type Server struct {
	opts Options
}

// New constructs the server, defaulting nil accessors to empty
// views so handlers never nil-check the Options themselves.
func New(opts Options) *Server {
	if opts.Snapshot == nil {
		opts.Snapshot = func() *neutron.Snapshot { return nil }
	}
	if opts.Trie == nil {
		opts.Trie = func() []neutron.TrieEntry { return nil }
	}
	if opts.Anomalies == nil {
		opts.Anomalies = func() *neutron.Anomalies { return nil }
	}
	if opts.LastSync == nil {
		opts.LastSync = func() time.Time { return time.Time{} }
	}
	if opts.MACLookup == nil {
		opts.MACLookup = func(uint64) (*metadata.TenantMeta, bool) { return nil, false }
	}
	return &Server{opts: opts}
}

// Handler returns the /debug route table. Patterns are rooted at
// /debug (not stripped), so the handler mounts on the agent's mux
// under both "/debug" (the exact index match) and "/debug/" (the
// subtree). Unmatched /debug paths fall through to opts.Fallback.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /debug/{$}", s.handleIndex)
	mux.HandleFunc("GET /debug", s.handleIndex)
	mux.HandleFunc("GET /debug/anomalies", s.handleAnomalies)
	mux.HandleFunc("GET /debug/lookup", s.handleLookup)
	mux.HandleFunc("GET /debug/zones", s.handleZones)
	mux.HandleFunc("GET /debug/topology", s.handleTopology)
	mux.HandleFunc("GET /debug/topology/{tenant}", s.handleTopologyTenant)

	// Stdlib pprof, the standard members of a Go admin mux. Index
	// serves the profile directory and routes named profiles
	// (heap, goroutine, ...) itself.
	mux.HandleFunc("GET /debug/pprof/", pprof.Index)
	mux.HandleFunc("GET /debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("GET /debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("GET /debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("GET /debug/pprof/trace", pprof.Trace)

	if s.opts.Fallback != nil {
		mux.Handle("/debug/", s.opts.Fallback)
	}
	return mux
}

// render writes model as the page's HTML by default, or as indented
// JSON when the request carries `?format=json`. Template errors are
// logged, not surfaced — headers are already written by the time
// Execute fails, so the status line cannot change.
func render(w http.ResponseWriter, r *http.Request, tmpl *template.Template, model any) {
	if r.URL.Query().Get(paramFormat) == formatJSON {
		w.Header().Set("Content-Type", "application/json")
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		if err := enc.Encode(model); err != nil {
			slog.Error("encode debug JSON failed",
				"component", componentDebug, "path", r.URL.Path, "err", err)
		}
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.Execute(w, model); err != nil {
		slog.Error("render debug page failed",
			"component", componentDebug, "path", r.URL.Path, "err", err)
	}
}

// parsePage parses one page template plus the shared style partial.
// Called from package-level template.Must vars so a malformed
// template fails at process start, not first request.
func parsePage(name string) *template.Template {
	return template.Must(template.New(name).
		ParseFS(templates, "templates/style.html", "templates/"+name))
}

// humanAge formats a duration as a short, fixed-width string:
// "47s", "3m", "2h13m". Days roll up into hours — the pages expect
// sync ages in minutes-to-hours, not days. A days-old sync is
// broken, not stale.
func humanAge(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	h := int(d / time.Hour)
	m := int((d % time.Hour) / time.Minute)
	if m == 0 {
		return fmt.Sprintf("%dh", h)
	}
	return fmt.Sprintf("%dh%dm", h, m)
}
