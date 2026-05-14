// Package logging configures the agent's structured logger.
//
// The package wraps stdlib log/slog: a [Handle] owns a [slog.LevelVar]
// (atomic, settable at runtime) and a [slog.Logger]. Init sets that
// logger as slog.Default so any package can call slog.Info/Warn/Error
// directly without plumbing the Handle through every constructor.
//
// To change the level at runtime, call [Handle.SetLevel]. The runtime
// package wires this to SIGHUP and an HTTP endpoint.
package logging

import (
	"fmt"
	"io"
	"log/slog"
	"strings"

	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/config"
)

// Handle is the runtime state of the agent's logging configuration.
// Init returns one and the runtime package uses it to change the level
// without restarting the agent.
type Handle struct {
	levelVar *slog.LevelVar
	logger   *slog.Logger
}

// Init builds a Handle from cfg, writes log records to w, and registers
// the resulting logger as slog.Default. Returns the Handle so the caller
// can change the level at runtime via [Handle.SetLevel].
//
// Subsequent calls replace the previous logger; mostly useful in tests.
func Init(cfg config.LoggingConfig, w io.Writer) (*Handle, error) {
	lvl, err := ParseLevel(cfg.Level)
	if err != nil {
		return nil, err
	}

	levelVar := new(slog.LevelVar)
	levelVar.Set(lvl)

	opts := &slog.HandlerOptions{Level: levelVar}
	var handler slog.Handler
	switch cfg.Format {
	case "json":
		handler = slog.NewJSONHandler(w, opts)
	case "text":
		handler = slog.NewTextHandler(w, opts)
	default:
		return nil, fmt.Errorf("logging: unknown format %q (want json or text)", cfg.Format)
	}

	logger := slog.New(handler)
	slog.SetDefault(logger)

	return &Handle{levelVar: levelVar, logger: logger}, nil
}

// Logger returns the slog.Logger associated with this handle. Identical
// to slog.Default unless Init has been called again since.
func (h *Handle) Logger() *slog.Logger {
	return h.logger
}

// SetLevel atomically updates the minimum level the logger emits. Safe to
// call concurrently with active log calls; backed by [slog.LevelVar].
func (h *Handle) SetLevel(s string) error {
	lvl, err := ParseLevel(s)
	if err != nil {
		return err
	}
	h.levelVar.Set(lvl)
	return nil
}

// CurrentLevel returns the level currently in effect as a lowercase string
// (e.g. "info", "debug"). Suitable for inclusion in /debug responses.
func (h *Handle) CurrentLevel() string {
	return strings.ToLower(h.levelVar.Level().String())
}

// ParseLevel parses one of "debug", "info", "warn", "error" (case
// insensitive) into the corresponding [slog.Level]. Returns an error for
// any other value.
func ParseLevel(s string) (slog.Level, error) {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("logging: invalid level %q (want debug, info, warn, or error)", s)
	}
}
