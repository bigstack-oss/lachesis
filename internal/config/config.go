// Package config holds the runtime configuration for the agent.
//
// The configuration is structured as nested sections — one Go file per
// section (http.go, bpf.go, scrape.go, logging.go, wal.go, neutron.go) —
// plus a top-level version envelope. Each section owns its type,
// defaults, and Validate method; this file aggregates them.
//
// Sources, in order of priority (later overrides earlier):
//
//   - built-in defaults
//   - YAML file (path from -config flag or <prefix>_CONFIG env var)
//   - environment variables (<prefix>_* — see load.go)
//   - CLI flags
//
// The default env prefix is "LACHESIS"; callers can override via
// [Options].EnvPrefix for forks or tests. The YAML file is the
// only "moving"
// source at runtime: SIGHUP triggers a re-read via [LoadYAML].
//
// Adding a new section (e.g. Neutron client, Kafka consumer):
//
//  1. Create a new file (e.g. neutron.go) with the section's type, its
//     defaults helper, and its Validate method.
//  2. Add the field to [Config] and to [Defaults].
//  3. Register the section's env vars and flags in load.go.
//  4. Add the section's Validate call to [Config.Validate].
package config

import (
	"fmt"

	"github.com/bigstack-oss/lachesis/internal/tunables"
)

// Config is the agent's complete runtime configuration.
type Config struct {
	Version    string           `yaml:"version"`
	HTTP       HTTPConfig       `yaml:"http"`
	BPF        BPFConfig        `yaml:"bpf"`
	Scrape     ScrapeConfig     `yaml:"scrape"`
	Logging    LoggingConfig    `yaml:"logging"`
	WAL        WALConfig        `yaml:"wal"`
	Neutron    NeutronConfig    `yaml:"neutron"`
	GC         GCConfig         `yaml:"gc"`
	Kafka      KafkaConfig      `yaml:"kafka"`
	Reconcile  ReconcileConfig  `yaml:"reconcile"`
	Unresolved UnresolvedConfig `yaml:"unresolved"`
}

// Defaults returns the production-ready configuration baseline. Each
// section's defaults helper lives in its own file.
func Defaults() Config {
	return Config{
		Version:    Version,
		HTTP:       httpDefaults(),
		BPF:        bpfDefaults(),
		Scrape:     scrapeDefaults(),
		Logging:    loggingDefaults(),
		WAL:        walDefaults(),
		Neutron:    neutronDefaults(),
		GC:         gcDefaults(),
		Kafka:      kafkaDefaults(),
		Reconcile:  reconcileDefaults(),
		Unresolved: unresolvedDefaults(),
	}
}

// Validate aggregates per-section validation. Each section's Validate
// method lives with its type. Subsection errors are wrapped with the
// section name for clarity.
func (c Config) Validate() error {
	if c.Version != Version {
		return fmt.Errorf("version %q unsupported (this binary handles %q)", c.Version, Version)
	}
	if err := c.HTTP.Validate(); err != nil {
		return fmt.Errorf("http: %w", err)
	}
	if err := c.BPF.Validate(); err != nil {
		return fmt.Errorf("bpf: %w", err)
	}
	if err := c.Scrape.Validate(); err != nil {
		return fmt.Errorf("scrape: %w", err)
	}
	if err := c.Logging.Validate(); err != nil {
		return fmt.Errorf("logging: %w", err)
	}
	if err := c.WAL.Validate(); err != nil {
		return fmt.Errorf("wal: %w", err)
	}
	if err := c.Neutron.Validate(); err != nil {
		return fmt.Errorf("neutron: %w", err)
	}
	if err := c.GC.Validate(); err != nil {
		return fmt.Errorf("gc: %w", err)
	}
	if err := c.Kafka.Validate(); err != nil {
		return fmt.Errorf("kafka: %w", err)
	}
	if err := c.Reconcile.Validate(); err != nil {
		return fmt.Errorf("reconcile: %w", err)
	}
	if err := c.Unresolved.Validate(); err != nil {
		return fmt.Errorf("unresolved: %w", err)
	}
	return nil
}

// Tunables projects the hot-reloadable subset of the (validated)
// config into the snapshot shape consumers read live. The projection
// is the single place that decides WHICH fields are hot — a field
// absent here is load-time by construction.
func (c Config) Tunables() tunables.Values {
	return tunables.Values{
		GhostGrace:            c.GC.GhostGrace,
		GhostSweepInterval:    c.GC.GhostSweepInterval,
		ServerCarryTTL:        c.GC.ServerCarryTTL,
		ReconcileInterval:     c.Reconcile.Interval,
		ScrapeInterval:        c.Scrape.Interval,
		WALFlushInterval:      c.WAL.FlushInterval,
		UnresolvedTTL:         c.Unresolved.TTL,
		UnresolvedCap:         c.Unresolved.Cap,
		PressureHighWatermark: c.GC.PressureHighWatermark,
		PressureLowWatermark:  c.GC.PressureLowWatermark,
		PressureMaxPerPass:    c.GC.PressureMaxPerPass,
	}
}
