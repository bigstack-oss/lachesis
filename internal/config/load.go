package config

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// DefaultEnvPrefix is used when [Options.EnvPrefix] is empty.
const DefaultEnvPrefix = "CUBECOS"

// Options customizes how [Load] resolves the configuration. The zero
// value is acceptable; missing fields are filled in with defaults.
type Options struct {
	// EnvPrefix is prepended to every env var name (e.g. "CUBECOS" yields
	// CUBECOS_HTTP_LISTEN). Empty means [DefaultEnvPrefix].
	EnvPrefix string
	// Getenv is the env-var lookup function. Empty means os.Getenv;
	// tests typically inject their own.
	Getenv func(string) string
}

// Load resolves the configuration from defaults, an optional YAML
// file, environment variables (prefixed with opts.EnvPrefix), and
// CLI flags, in that order; later sources override earlier.
//
// Pass [Options]{} for the production-default behaviour; tests and
// forks supply a custom EnvPrefix or Getenv via the same struct.
//
// The YAML file path is sourced from the -config flag if present in
// args, otherwise from <prefix>_CONFIG. If neither is set, the YAML
// layer is skipped.
//
// The returned Config has already been validated; callers can use
// it without further checks.
func Load(opts Options, args []string) (Config, error) {
	if opts.EnvPrefix == "" {
		opts.EnvPrefix = DefaultEnvPrefix
	}
	if opts.Getenv == nil {
		opts.Getenv = os.Getenv
	}

	cfg := Defaults()

	configPath := findConfigPath(args, opts.Getenv(opts.EnvPrefix+"_CONFIG"))

	if configPath != "" {
		loaded, err := LoadYAML(configPath)
		if err != nil {
			return cfg, fmt.Errorf("config: %w", err)
		}
		cfg = loaded
	}

	if err := applyEnv(&cfg, opts.EnvPrefix, opts.Getenv); err != nil {
		return cfg, fmt.Errorf("config: %w", err)
	}

	if err := applyFlags(&cfg, &configPath, args, opts.EnvPrefix); err != nil {
		return cfg, fmt.Errorf("config: %w", err)
	}

	return cfg, cfg.Validate()
}

// FindConfigPath returns the YAML config-file path that [Load]
// would resolve from args and the environment. Exposed so callers
// can pass the same path to [runtime.New] for SIGHUP reload.
//
// Argument order matches [Load] (opts first, args second) so the
// two functions read consistently at call sites.
func FindConfigPath(opts Options, args []string) string {
	if opts.EnvPrefix == "" {
		opts.EnvPrefix = DefaultEnvPrefix
	}
	if opts.Getenv == nil {
		opts.Getenv = os.Getenv
	}
	return findConfigPath(args, opts.Getenv(opts.EnvPrefix+"_CONFIG"))
}

// LoadYAML reads and parses a YAML config file, starting from [Defaults]
// and overlaying any fields the file specifies. Unknown YAML keys are
// rejected as typos. Used by [Load] and by SIGHUP reload.
func LoadYAML(path string) (Config, error) {
	cfg := Defaults()
	b, err := os.ReadFile(path)
	if err != nil {
		return cfg, fmt.Errorf("read %s: %w", path, err)
	}
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return cfg, fmt.Errorf("parse %s: %w", path, err)
	}
	return cfg, nil
}

// findConfigPath scans args for -config / --config (with or without =)
// and returns its value. If not present, returns envFallback.
func findConfigPath(args []string, envFallback string) string {
	for i, a := range args {
		switch {
		case a == "-config" || a == "--config":
			if i+1 < len(args) {
				return args[i+1]
			}
		case strings.HasPrefix(a, "-config="):
			return strings.TrimPrefix(a, "-config=")
		case strings.HasPrefix(a, "--config="):
			return strings.TrimPrefix(a, "--config=")
		}
	}
	return envFallback
}

// applyEnv overlays env-var values onto cfg, using prefix for the
// variable namespace. Returns an error only for malformed values
// (e.g. an unparseable duration).
//
// Each section's env-var bindings are declared here together so the
// "what is configurable from the environment" question has one answer.
func applyEnv(cfg *Config, prefix string, getenv func(string) string) error {
	if v := getenv(prefix + "_HTTP_LISTEN"); v != "" {
		cfg.HTTP.Listen = v
	}
	if v := getenv(prefix + "_BPF_PIN_PATH"); v != "" {
		cfg.BPF.PinPath = v
	}
	if v := getenv(prefix + "_BPF_ATTACH_INTERFACE"); v != "" {
		cfg.BPF.AttachInterface = v
	}
	if v := getenv(prefix + "_SCRAPE_INTERVAL"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return fmt.Errorf("%s_SCRAPE_INTERVAL=%q: %w", prefix, v, err)
		}
		cfg.Scrape.Interval = d
	}
	if v := getenv(prefix + "_LOG_LEVEL"); v != "" {
		cfg.Logging.Level = v
	}
	if v := getenv(prefix + "_LOG_FORMAT"); v != "" {
		cfg.Logging.Format = v
	}
	return nil
}

// applyFlags binds each configurable field to a CLI flag and parses
// args. Flag descriptions include the matching env-var name so
// `agent -help` shows both. Each section's flag bindings are declared
// here together for the same reason as [applyEnv].
func applyFlags(cfg *Config, configPath *string, args []string, envPrefix string) error {
	fs := flag.NewFlagSet("agent", flag.ContinueOnError)
	envHint := func(suffix string) string {
		return fmt.Sprintf(" (env: %s_%s)", envPrefix, suffix)
	}
	fs.StringVar(configPath, "config", *configPath,
		"Path to YAML config file"+envHint("CONFIG"))
	fs.StringVar(&cfg.HTTP.Listen, "http-listen", cfg.HTTP.Listen,
		"HTTP listen address"+envHint("HTTP_LISTEN"))
	fs.StringVar(&cfg.BPF.PinPath, "bpf-pin-path", cfg.BPF.PinPath,
		"BPF FS pin directory"+envHint("BPF_PIN_PATH"))
	fs.StringVar(&cfg.BPF.AttachInterface, "bpf-attach-interface", cfg.BPF.AttachInterface,
		"Host interface to attach TC clsact + telemetry programs on; empty disables attach"+envHint("BPF_ATTACH_INTERFACE"))
	fs.DurationVar(&cfg.Scrape.Interval, "scrape-interval", cfg.Scrape.Interval,
		"Scrape interval"+envHint("SCRAPE_INTERVAL"))
	fs.StringVar(&cfg.Logging.Level, "log-level", cfg.Logging.Level,
		"Log level: debug, info, warn, error"+envHint("LOG_LEVEL"))
	fs.StringVar(&cfg.Logging.Format, "log-format", cfg.Logging.Format,
		"Log format: json, text"+envHint("LOG_FORMAT"))
	return fs.Parse(args)
}
