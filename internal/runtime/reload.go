// Package runtime wires reload and debug controls onto the agent.
//
// It exposes a [Manager] that holds the current [config.Config] snapshot,
// re-reads the YAML on SIGHUP, applies hot-reloadable fields, and serves
// /debug HTTP endpoints for ad-hoc runtime tuning.
//
// Hot vs load-time fields:
//
//   - Hot: applied immediately on reload. Today: logging.level and the
//     gc.* pressure-relief tunables (via the [PressureTunable] seam).
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

// PressureTunable receives hot-reloaded pressure-relief parameters. The
// GC's pressure reliever implements it; the agent wires the instance via
// [Manager.SetPressureTunable]. Defined here (the consumer) so the
// runtime package needs no dependency on the gc package.
type PressureTunable interface {
	SetPressureParams(high, low float64, maxPerPass int)
}

// Manager owns the agent's runtime configuration state. Construct one in
// main after [config.Load] and [logging.Init], then call [Manager.InstallSIGHUP]
// and mount [Manager.DebugHandler] on the HTTP server.
type Manager struct {
	mu         sync.Mutex
	configPath string        // YAML path; empty disables SIGHUP reload
	current    config.Config // last applied snapshot
	log        *logging.Handle
	pressure   PressureTunable // nil off-Linux, where no reliever runs
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

// SetPressureTunable wires the pressure-relief reliever so SIGHUP
// reloads of the gc.* fields apply live. Call once during boot, before
// [Manager.InstallSIGHUP]. A nil tunable (off-Linux, where no reliever
// runs) leaves the gc.* fields effectively load-time.
func (m *Manager) SetPressureTunable(t PressureTunable) {
	m.mu.Lock()
	m.pressure = t
	m.mu.Unlock()
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
		slog.Info("logging.level changed",
			"component", componentReload,
			"from", m.current.Logging.Level, "to", next.Logging.Level)
	}

	if next.GC != m.current.GC {
		if m.pressure != nil {
			m.pressure.SetPressureParams(
				next.GC.PressureHighWatermark,
				next.GC.PressureLowWatermark,
				next.GC.PressureMaxPerPass)
		}
		slog.Info("gc pressure params changed",
			"component", componentReload,
			"high", next.GC.PressureHighWatermark,
			"low", next.GC.PressureLowWatermark,
			"max_per_pass", next.GC.PressureMaxPerPass)
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
	slog.Warn("load-time field change ignored; restart required",
		"component", componentReload,
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
					slog.Warn("SIGHUP reload failed", "component", componentReload, "err", err)
					continue
				}
				slog.Info("SIGHUP reload applied", "component", componentReload)
			}
		}
	}()
}

// DebugHandler returns the http.Handler exposing the /debug endpoints:
//
//	GET  /debug/config     returns the active Config as JSON (secrets redacted)
//	PUT  /debug/log-level  body: {"level":"debug|info|warn|error"} — change level at runtime
//
// Mount it on the agent's HTTP server alongside /metrics.
//
// Security posture: the endpoints are intentionally unauthenticated,
// and the server's default listen address is all-interfaces so
// Prometheus can scrape /metrics. Secrets never appear in responses
// ([config.NeutronConfig.MarshalJSON] redacts them), but on untrusted
// networks operators must still bind http.listen to localhost or
// firewall the port — /debug also exposes pprof and runtime tuning.
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
		slog.Warn("encode /debug/config", "component", componentDebug, "err", err)
	}
}

func (m *Manager) handlePutLogLevel(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Level string `json:"level"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, logLevelMaxBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			http.Error(w, "body too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "invalid json body: "+err.Error(), http.StatusBadRequest)
		return
	}
	// Hold m.mu across both the level-var update and the m.current
	// write so they move together. Reload takes the same lock while it
	// reads m.current.Logging.Level to detect a transition and calls
	// SetLevel; without the lock here, a concurrent SIGHUP reload could
	// interleave and leave the live level var disagreeing with the
	// snapshot (and mislog the transition). SetLevel is an atomic
	// LevelVar store, not IO, so holding the lock across it is cheap and
	// cannot deadlock against Reload.
	m.mu.Lock()
	if err := m.log.SetLevel(body.Level); err != nil {
		m.mu.Unlock()
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	m.current.Logging.Level = body.Level
	m.mu.Unlock()

	slog.Info("logging.level changed via /debug", "component", componentDebug, "level", body.Level)
	w.WriteHeader(http.StatusNoContent)
}
