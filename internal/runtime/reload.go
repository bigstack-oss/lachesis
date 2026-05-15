// Package runtime wires reload and debug controls onto the agent.
//
// It exposes a [Manager] that holds the current [config.Config] snapshot,
// re-reads the YAML on SIGHUP, applies hot-reloadable fields, and serves
// /debug HTTP endpoints for ad-hoc runtime tuning.
//
// Hot vs load-time fields:
//
//   - Hot: applied immediately on reload. Today: logging.level.
//   - Load-time: change in the YAML is logged as a warning and ignored;
//     restart is required for it to take effect. Today: http.listen,
//     bpf.pin_path, scrape.interval (until the scraper supports retiming),
//     logging.format.
//
// Hot fields are extended over time as subsystems add the necessary
// atomic plumbing.
package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/config"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/logging"
)

// Manager owns the agent's runtime configuration state. Construct one in
// main after [config.Load] and [logging.Init], then call [Manager.InstallSIGHUP]
// and mount [Manager.DebugHandler] on the HTTP server.
type Manager struct {
	mu         sync.Mutex
	configPath string        // YAML path; empty disables SIGHUP reload
	current    config.Config // last applied snapshot
	log        *logging.Handle
}

// New creates a Manager seeded with the initial config snapshot. The
// configPath is the YAML file location; an empty string disables SIGHUP
// reload while keeping the /debug HTTP endpoints functional.
func New(configPath string, initial config.Config, log *logging.Handle) *Manager {
	return &Manager{
		configPath: configPath,
		current:    initial,
		log:        log,
	}
}

// Current returns a snapshot of the most recently applied configuration.
// Safe for concurrent callers.
func (m *Manager) Current() config.Config {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.current
}

// Reload reads the YAML file and applies hot-reloadable fields. Load-time
// fields whose YAML value differs from the running value are logged as
// warnings but not applied; restart is required for those.
//
// Returns an error if the YAML cannot be read or fails validation. The
// active configuration is left unchanged in that case.
func (m *Manager) Reload() error {
	if m.configPath == "" {
		return errors.New("runtime: reload disabled (no config file)")
	}
	next, err := config.LoadYAML(m.configPath)
	if err != nil {
		return err
	}
	if err := next.Validate(); err != nil {
		return fmt.Errorf("runtime: new config invalid: %w", err)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if next.Logging.Level != m.current.Logging.Level {
		if err := m.log.SetLevel(next.Logging.Level); err != nil {
			return fmt.Errorf("runtime: apply logging.level: %w", err)
		}
		slog.Info("reload: logging.level changed",
			"from", m.current.Logging.Level, "to", next.Logging.Level)
	}

	warnLoadTimeChange("http.listen", m.current.HTTP.Listen, next.HTTP.Listen)
	warnLoadTimeChange("bpf.pin_path", m.current.BPF.PinPath, next.BPF.PinPath)
	warnLoadTimeChange("scrape.interval",
		m.current.Scrape.Interval.String(), next.Scrape.Interval.String())
	warnLoadTimeChange("logging.format", m.current.Logging.Format, next.Logging.Format)

	m.current = next
	return nil
}

func warnLoadTimeChange(field, current, fromYAML string) {
	if current == fromYAML {
		return
	}
	slog.Warn("reload: load-time field change ignored; restart required",
		"field", field, "running", current, "yaml", fromYAML)
}

// InstallSIGHUP installs a handler that calls [Manager.Reload] on each
// SIGHUP. The goroutine stops when ctx is cancelled. Safe to call once
// per process; not concurrency-safe with itself.
func (m *Manager) InstallSIGHUP(ctx context.Context) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGHUP)
	go func() {
		defer signal.Stop(ch)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ch:
				if err := m.Reload(); err != nil {
					slog.Warn("SIGHUP reload failed", "err", err)
					continue
				}
				slog.Info("SIGHUP reload applied")
			}
		}
	}()
}

// DebugHandler returns the http.Handler exposing the /debug endpoints:
//
//	GET  /debug/config     returns the active Config as JSON
//	PUT  /debug/log-level  body: {"level":"debug|info|warn|error"} — change level at runtime
//
// Mount it on the agent's HTTP server alongside /metrics. The endpoints
// are intentionally not authenticated; bind the HTTP server to localhost
// or behind a reverse proxy if the host is untrusted.
func (m *Manager) DebugHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /debug/config", m.handleGetConfig)
	mux.HandleFunc("PUT /debug/log-level", m.handlePutLogLevel)
	return mux
}

func (m *Manager) handleGetConfig(w http.ResponseWriter, _ *http.Request) {
	cur := m.Current()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(cur); err != nil {
		slog.Warn("debug: encode /debug/config", "err", err)
	}
}

func (m *Manager) handlePutLogLevel(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Level string `json:"level"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid json body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := m.log.SetLevel(body.Level); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	m.mu.Lock()
	m.current.Logging.Level = body.Level
	m.mu.Unlock()

	slog.Info("logging.level changed via /debug", "level", body.Level)
	w.WriteHeader(http.StatusNoContent)
}
