// Package config holds the runtime configuration for the agent.
//
// The configuration is structured as nested sections — one Go file per
// section (http.go, bpf.go, scrape.go, logging.go) — plus a top-level
// version envelope. Each section owns its type, defaults, and Validate
// method; this file aggregates them.
//
// Sources, in order of priority (later overrides earlier):
//
//   - built-in defaults
//   - YAML file (path from -config flag or <prefix>_CONFIG env var)
//   - environment variables (<prefix>_* — see load.go)
//   - CLI flags
//
// The default env prefix is "CUBECOS"; callers can override via
// [LoadWith] for forks or tests. The YAML file is the only "moving"
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

import "fmt"

// Version is the configuration schema version this binary understands.
// Bumped only on breaking schema changes; consumers gate on it.
const Version = "1"

// Config is the agent's complete runtime configuration.
type Config struct {
	Version string        `yaml:"version"`
	HTTP    HTTPConfig    `yaml:"http"`
	BPF     BPFConfig     `yaml:"bpf"`
	Scrape  ScrapeConfig  `yaml:"scrape"`
	Logging LoggingConfig `yaml:"logging"`
}

// Defaults returns the production-ready configuration baseline. Each
// section's defaults helper lives in its own file.
func Defaults() Config {
	return Config{
		Version: Version,
		HTTP:    httpDefaults(),
		BPF:     bpfDefaults(),
		Scrape:  scrapeDefaults(),
		Logging: loggingDefaults(),
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
	return nil
}
