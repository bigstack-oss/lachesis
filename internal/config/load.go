package config

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

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

	configPath := findConfigPath(args, opts.Getenv(opts.EnvPrefix+"_"+envConfig))

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
//
// Invariant: this MUST return the same path [Load] actually reads YAML
// from. SIGHUP reload watches this result while [Load] loaded its own
// internally-resolved path, so any divergence would make reload
// re-read a different file than the one that booted the agent. Both
// delegate to findConfigPath; keep it that way. Pinned by
// TestFindConfigPathMatchesLoad.
func FindConfigPath(opts Options, args []string) string {
	if opts.EnvPrefix == "" {
		opts.EnvPrefix = DefaultEnvPrefix
	}
	if opts.Getenv == nil {
		opts.Getenv = os.Getenv
	}
	return findConfigPath(args, opts.Getenv(opts.EnvPrefix+"_"+envConfig))
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
	if v := getenv(prefix + "_" + envHTTPListen); v != "" {
		cfg.HTTP.Listen = v
	}
	if v := getenv(prefix + "_" + envBPFPinPath); v != "" {
		cfg.BPF.PinPath = v
	}
	if v := getenv(prefix + "_" + envBPFAttachPrefixes); v != "" {
		cfg.BPF.AttachPrefixes = splitList(v)
	}
	if v := getenv(prefix + "_" + envBPFAttachInterfaces); v != "" {
		cfg.BPF.AttachInterfaces = splitList(v)
	}
	if v := getenv(prefix + "_" + envScrapeInterval); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return fmt.Errorf("%s_%s=%q: %w", prefix, envScrapeInterval, v, err)
		}
		cfg.Scrape.Interval = d
	}
	if v := getenv(prefix + "_" + envLogLevel); v != "" {
		cfg.Logging.Level = v
	}
	if v := getenv(prefix + "_" + envLogFormat); v != "" {
		cfg.Logging.Format = v
	}
	if v := getenv(prefix + "_" + envWALPath); v != "" {
		cfg.WAL.Path = v
	}
	if v := getenv(prefix + "_" + envWALFlushInterval); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return fmt.Errorf("%s_%s=%q: %w", prefix, envWALFlushInterval, v, err)
		}
		cfg.WAL.FlushInterval = d
	}
	if v := getenv(prefix + "_" + envWALEnabled); v != "" {
		b, err := parseBool(v)
		if err != nil {
			return fmt.Errorf("%s_%s=%q: %w", prefix, envWALEnabled, v, err)
		}
		cfg.WAL.Enabled = b
	}
	if v := getenv(prefix + "_" + envNeutronEnabled); v != "" {
		b, err := parseBool(v)
		if err != nil {
			return fmt.Errorf("%s_%s=%q: %w", prefix, envNeutronEnabled, v, err)
		}
		cfg.Neutron.Enabled = b
	}
	if v := getenv(prefix + "_" + envNeutronCredentialsFile); v != "" {
		cfg.Neutron.CredentialsFile = v
	}
	if v := getenv(prefix + "_" + envNeutronUnsafeAllowAmbiguousRoutes); v != "" {
		b, err := parseBool(v)
		if err != nil {
			return fmt.Errorf("%s_%s=%q: %w", prefix, envNeutronUnsafeAllowAmbiguousRoutes, v, err)
		}
		cfg.Neutron.UnsafeAllowAmbiguousRoutes = b
	}
	return nil
}

// parseBool accepts the same forms strconv.ParseBool does ("1",
// "true", "false", etc.) plus the YAML-style "yes" / "no" that
// operators often type in env vars by habit.
func parseBool(s string) (bool, error) {
	switch strings.ToLower(s) {
	case "1", "t", "true", "y", "yes", "on":
		return true, nil
	case "0", "f", "false", "n", "no", "off":
		return false, nil
	}
	return false, fmt.Errorf("not a boolean")
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
		"Path to YAML config file"+envHint(envConfig))
	fs.StringVar(&cfg.HTTP.Listen, "http-listen", cfg.HTTP.Listen,
		"HTTP listen address"+envHint(envHTTPListen))
	fs.StringVar(&cfg.BPF.PinPath, "bpf-pin-path", cfg.BPF.PinPath,
		"BPF FS pin directory"+envHint(envBPFPinPath))
	// The allowlist fields are []string; bind them via comma-separated
	// scratch strings and split back after Parse (the flag package has
	// no native string-slice). Defaults round-trip through Join/split.
	prefixesFlag := strings.Join(cfg.BPF.AttachPrefixes, ",")
	fs.StringVar(&prefixesFlag, "bpf-attach-prefixes", prefixesFlag,
		"Comma-separated interface-name prefixes the netlink subscriber attaches to"+envHint(envBPFAttachPrefixes))
	interfacesFlag := strings.Join(cfg.BPF.AttachInterfaces, ",")
	fs.StringVar(&interfacesFlag, "bpf-attach-interfaces", interfacesFlag,
		"Comma-separated explicit interface-name allowlist for the netlink subscriber"+envHint(envBPFAttachInterfaces))
	fs.DurationVar(&cfg.Scrape.Interval, "scrape-interval", cfg.Scrape.Interval,
		"Scrape interval"+envHint(envScrapeInterval))
	fs.StringVar(&cfg.Logging.Level, "log-level", cfg.Logging.Level,
		"Log level: debug, info, warn, error"+envHint(envLogLevel))
	fs.StringVar(&cfg.Logging.Format, "log-format", cfg.Logging.Format,
		"Log format: json, text"+envHint(envLogFormat))
	fs.StringVar(&cfg.WAL.Path, "wal-path", cfg.WAL.Path,
		"WAL snapshot file (absolute path)"+envHint(envWALPath))
	fs.DurationVar(&cfg.WAL.FlushInterval, "wal-flush-interval", cfg.WAL.FlushInterval,
		"WAL flush cadence"+envHint(envWALFlushInterval))
	fs.BoolVar(&cfg.WAL.Enabled, "wal-enabled", cfg.WAL.Enabled,
		"Enable WAL persistence (boot-restore + periodic flush)"+envHint(envWALEnabled))
	fs.BoolVar(&cfg.Neutron.Enabled, "neutron-enabled", cfg.Neutron.Enabled,
		"Enable Neutron cold-start (boot-blocking)"+envHint(envNeutronEnabled))
	fs.StringVar(&cfg.Neutron.CredentialsFile, "neutron-credentials-file", cfg.Neutron.CredentialsFile,
		"Absolute path to admin-openrc-style credentials file"+envHint(envNeutronCredentialsFile))
	fs.BoolVar(&cfg.Neutron.UnsafeAllowAmbiguousRoutes, "unsafe-allow-ambiguous-routes", cfg.Neutron.UnsafeAllowAmbiguousRoutes,
		"Allow boot to continue when BuildTrie reports static-route Step C ambiguities; default false (strict)"+envHint(envNeutronUnsafeAllowAmbiguousRoutes))
	if err := fs.Parse(args); err != nil {
		return err
	}
	// Only overwrite when the flag carried a value, so an unset flag
	// leaves the default / YAML / env-resolved slice untouched — and
	// in particular preserves the empty-but-non-nil AttachInterfaces
	// default that the example-YAML drift test depends on. This mirrors
	// applyEnv's `if v != ""` guard above.
	if prefixesFlag != "" {
		cfg.BPF.AttachPrefixes = splitList(prefixesFlag)
	}
	if interfacesFlag != "" {
		cfg.BPF.AttachInterfaces = splitList(interfacesFlag)
	}
	return nil
}

// splitList parses a comma-separated flag/env value into a trimmed,
// empty-free string slice.
func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
