package config_test

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/bigstack-oss/lachesis/internal/config"
)

func TestDefaultsValidate(t *testing.T) {
	cfg := config.Defaults()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("defaults must validate: %v", err)
	}
	if cfg.Version != config.Version {
		t.Errorf("Version = %q, want %q", cfg.Version, config.Version)
	}
}

// TestExampleYAMLMatchesDefaults guards the operator-facing
// deploy/agent/config.example.yaml against drift: the parsed file
// must exactly equal config.Defaults(). Update one without the other
// and this test fires.
func TestExampleYAMLMatchesDefaults(t *testing.T) {
	const path = "../../deploy/agent/config.example.yaml"
	cfg, err := config.LoadYAML(path)
	if err != nil {
		t.Fatalf("LoadYAML(%s): %v", path, err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("example YAML must validate: %v", err)
	}
	if !reflect.DeepEqual(cfg, config.Defaults()) {
		t.Errorf("example YAML drift:\n  yaml:     %+v\n  defaults: %+v", cfg, config.Defaults())
	}
}

func TestLoadDefaultsOnly(t *testing.T) {
	// No flags, no env, no yaml — should match Defaults().
	clearEnv(t)
	cfg, err := config.Load(config.Options{}, nil)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := config.Defaults()
	if !reflect.DeepEqual(cfg, want) {
		t.Errorf("cfg = %+v, want %+v", cfg, want)
	}
}

func TestLoadFromEnv(t *testing.T) {
	clearEnv(t)
	t.Setenv("LACHESIS_HTTP_LISTEN", ":9200")
	t.Setenv("LACHESIS_SCRAPE_INTERVAL", "30s")
	t.Setenv("LACHESIS_LOG_LEVEL", "warn")
	t.Setenv("LACHESIS_LOG_FORMAT", "text")

	cfg, err := config.Load(config.Options{}, nil)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.HTTP.Listen != ":9200" {
		t.Errorf("HTTP.Listen = %q, want :9200", cfg.HTTP.Listen)
	}
	if cfg.Scrape.Interval != 30*time.Second {
		t.Errorf("Scrape.Interval = %v, want 30s", cfg.Scrape.Interval)
	}
	if cfg.Logging.Level != "warn" {
		t.Errorf("Logging.Level = %q, want warn", cfg.Logging.Level)
	}
	if cfg.Logging.Format != "text" {
		t.Errorf("Logging.Format = %q, want text", cfg.Logging.Format)
	}
}

func TestLoadFromFlags(t *testing.T) {
	clearEnv(t)
	args := []string{
		"-http-listen", ":9300",
		"-bpf-pin-path", "/var/run/bpf/telemetry",
		"-scrape-interval", "5s",
		"-log-level", "debug",
		"-log-format", "text",
	}
	cfg, err := config.Load(config.Options{}, args)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.HTTP.Listen != ":9300" {
		t.Errorf("HTTP.Listen = %q", cfg.HTTP.Listen)
	}
	if cfg.BPF.PinPath != "/var/run/bpf/telemetry" {
		t.Errorf("BPF.PinPath = %q", cfg.BPF.PinPath)
	}
	if cfg.Scrape.Interval != 5*time.Second {
		t.Errorf("Scrape.Interval = %v", cfg.Scrape.Interval)
	}
	if cfg.Logging.Level != "debug" {
		t.Errorf("Logging.Level = %q", cfg.Logging.Level)
	}
	if cfg.Logging.Format != "text" {
		t.Errorf("Logging.Format = %q", cfg.Logging.Format)
	}
}

func TestLoadFromYAML(t *testing.T) {
	clearEnv(t)
	path := writeYAML(t, `
version: "1"
http:
  listen: ":9400"
bpf:
  pin_path: /opt/bpf/cube
scrape:
  interval: 15s
logging:
  level: warn
  format: text
`)
	cfg, err := config.Load(config.Options{}, []string{"-config", path})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.HTTP.Listen != ":9400" {
		t.Errorf("HTTP.Listen = %q", cfg.HTTP.Listen)
	}
	if cfg.BPF.PinPath != "/opt/bpf/cube" {
		t.Errorf("BPF.PinPath = %q", cfg.BPF.PinPath)
	}
	if cfg.Scrape.Interval != 15*time.Second {
		t.Errorf("Scrape.Interval = %v", cfg.Scrape.Interval)
	}
	if cfg.Logging.Level != "warn" || cfg.Logging.Format != "text" {
		t.Errorf("Logging = %+v", cfg.Logging)
	}
}

func TestLoadPartialYAMLFillsDefaults(t *testing.T) {
	clearEnv(t)
	// Only http.listen is set in YAML; other fields should fall back to defaults.
	path := writeYAML(t, `
version: "1"
http:
  listen: ":9500"
`)
	cfg, err := config.Load(config.Options{}, []string{"-config", path})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.HTTP.Listen != ":9500" {
		t.Errorf("HTTP.Listen = %q", cfg.HTTP.Listen)
	}
	if cfg.BPF.PinPath != "/sys/fs/bpf/telemetry" {
		t.Errorf("BPF.PinPath = %q, expected default", cfg.BPF.PinPath)
	}
	if cfg.Scrape.Interval != 10*time.Second {
		t.Errorf("Scrape.Interval = %v, expected 10s default", cfg.Scrape.Interval)
	}
}

func TestPrecedenceFlagOverEnvOverYAML(t *testing.T) {
	clearEnv(t)
	path := writeYAML(t, `
version: "1"
http:
  listen: ":1111"
`)
	t.Setenv("LACHESIS_HTTP_LISTEN", ":2222")

	// All three sources set http.listen — flag should win.
	cfg, err := config.Load(config.Options{}, []string{"-config", path, "-http-listen", ":3333"})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.HTTP.Listen != ":3333" {
		t.Errorf("flag should win: got %q", cfg.HTTP.Listen)
	}

	// Without the flag, env should win over YAML.
	cfg, err = config.Load(config.Options{}, []string{"-config", path})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.HTTP.Listen != ":2222" {
		t.Errorf("env should win over yaml: got %q", cfg.HTTP.Listen)
	}
}

func TestLoadYAMLRejectsUnknownFields(t *testing.T) {
	path := writeYAML(t, `
version: "1"
http:
  listen: ":9090"
  oops: typo
`)
	if _, err := config.LoadYAML(path); err == nil {
		t.Fatal("expected error for unknown YAML field, got nil")
	} else if !strings.Contains(err.Error(), "oops") {
		t.Errorf("error should mention the unknown field, got: %v", err)
	}
}

func TestLoadRejectsBadEnv(t *testing.T) {
	clearEnv(t)
	t.Setenv("LACHESIS_SCRAPE_INTERVAL", "not-a-duration")
	if _, err := config.Load(config.Options{}, nil); err == nil {
		t.Fatal("expected error for malformed env value, got nil")
	}
}

func TestLoad_CustomEnvPrefix(t *testing.T) {
	clearEnv(t)
	getenv := func(key string) string {
		switch key {
		case "ACME_HTTP_LISTEN":
			return ":7777"
		case "ACME_LOG_LEVEL":
			return "warn"
		}
		return ""
	}
	cfg, err := config.Load(config.Options{EnvPrefix: "ACME", Getenv: getenv}, nil)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.HTTP.Listen != ":7777" {
		t.Errorf("HTTP.Listen = %q, want :7777", cfg.HTTP.Listen)
	}
	if cfg.Logging.Level != "warn" {
		t.Errorf("Logging.Level = %q, want warn", cfg.Logging.Level)
	}
}

func TestLoad_ZeroOptsUsesDefaultPrefix(t *testing.T) {
	clearEnv(t)
	getenv := func(key string) string {
		if key == "LACHESIS_HTTP_LISTEN" {
			return ":8888"
		}
		return ""
	}
	cfg, err := config.Load(config.Options{Getenv: getenv}, nil)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.HTTP.Listen != ":8888" {
		t.Errorf("HTTP.Listen = %q, want :8888 (default prefix applied)", cfg.HTTP.Listen)
	}
}

func TestLoad_CustomPrefixDoesNotReadLachesis(t *testing.T) {
	clearEnv(t)
	t.Setenv("LACHESIS_HTTP_LISTEN", ":9999")
	getenv := func(key string) string { return os.Getenv(key) }
	cfg, err := config.Load(config.Options{EnvPrefix: "ACME", Getenv: getenv}, nil)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.HTTP.Listen != ":9090" {
		t.Errorf("HTTP.Listen = %q, want :9090 (LACHESIS_ should be ignored under ACME prefix)", cfg.HTTP.Listen)
	}
}

func TestDefaultEnvPrefix(t *testing.T) {
	if config.DefaultEnvPrefix != "LACHESIS" {
		t.Errorf("DefaultEnvPrefix = %q, want LACHESIS", config.DefaultEnvPrefix)
	}
}

func TestValidate(t *testing.T) {
	cases := []struct {
		name      string
		mut       func(*config.Config)
		errSubstr string
	}{
		{"unsupported version", func(c *config.Config) { c.Version = "99" }, "version"},
		{"empty http listen", func(c *config.Config) { c.HTTP.Listen = "" }, "http"},
		{"bad http listen", func(c *config.Config) { c.HTTP.Listen = "not-host-port" }, "http"},
		{"empty bpf path", func(c *config.Config) { c.BPF.PinPath = "" }, "bpf"},
		{"relative bpf path", func(c *config.Config) { c.BPF.PinPath = "relative/path" }, "bpf"},
		{"sub-second scrape", func(c *config.Config) { c.Scrape.Interval = 100 * time.Millisecond }, "scrape"},
		{"bad log level", func(c *config.Config) { c.Logging.Level = "verbose" }, "logging"},
		{"bad log format", func(c *config.Config) { c.Logging.Format = "xml" }, "logging"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Defaults()
			tc.mut(&cfg)
			err := cfg.Validate()
			if err == nil {
				t.Fatal("expected validation error, got nil")
			}
			if !strings.Contains(err.Error(), tc.errSubstr) {
				t.Errorf("error should mention %q, got: %v", tc.errSubstr, err)
			}
		})
	}
}

// TestFindConfigPathMatchesLoad pins the invariant that FindConfigPath
// returns the exact path Load reads YAML from. runtime.New watches
// FindConfigPath's result for SIGHUP reload while Load loaded its own
// internally-resolved path; a divergence would make reload re-read a
// different file than the one that booted the agent. The two share
// findConfigPath today, but nothing else enforces the agreement.
func TestFindConfigPathMatchesLoad(t *testing.T) {
	clearEnv(t)
	path := writeYAML(t, `
version: "1"
http:
  listen: ":9610"
`)
	for _, args := range [][]string{
		{"-config", path},
		{"-config=" + path},
	} {
		if got := config.FindConfigPath(config.Options{}, args); got != path {
			t.Errorf("FindConfigPath(%v) = %q, want %q", args, got, path)
		}
		// The marker listen value Defaults() never produces proves Load
		// actually read the file at FindConfigPath's path.
		cfg, err := config.Load(config.Options{}, args)
		if err != nil {
			t.Fatalf("Load(%v): %v", args, err)
		}
		if cfg.HTTP.Listen != ":9610" {
			t.Errorf("Load(%v) read a different file: HTTP.Listen = %q, want :9610", args, cfg.HTTP.Listen)
		}
	}
}

// TestLoadAttachAllowlistFromEnvAndFlags covers the env + flag bindings
// for the attach allowlist (attach_prefixes / attach_interfaces) — the
// way a non-YAML deployment reaches the allowlist.
func TestLoadAttachAllowlistFromEnvAndFlags(t *testing.T) {
	clearEnv(t)
	// Env: comma-separated lists, trimmed, override the ["tap"] default.
	t.Setenv("LACHESIS_BPF_ATTACH_PREFIXES", "tap, qvo")
	t.Setenv("LACHESIS_BPF_ATTACH_INTERFACES", "veth-test")
	cfg, err := config.Load(config.Options{}, nil)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !reflect.DeepEqual(cfg.BPF.AttachPrefixes, []string{"tap", "qvo"}) {
		t.Errorf("AttachPrefixes = %v, want [tap qvo]", cfg.BPF.AttachPrefixes)
	}
	if !reflect.DeepEqual(cfg.BPF.AttachInterfaces, []string{"veth-test"}) {
		t.Errorf("AttachInterfaces = %v, want [veth-test]", cfg.BPF.AttachInterfaces)
	}

	// Flag wins over env.
	clearEnv(t)
	t.Setenv("LACHESIS_BPF_ATTACH_PREFIXES", "qvo")
	cfg, err = config.Load(config.Options{}, []string{"-bpf-attach-prefixes", "tap,eth"})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !reflect.DeepEqual(cfg.BPF.AttachPrefixes, []string{"tap", "eth"}) {
		t.Errorf("flag should win: AttachPrefixes = %v, want [tap eth]", cfg.BPF.AttachPrefixes)
	}

	// Default preserved when neither env nor flag is set.
	clearEnv(t)
	cfg, err = config.Load(config.Options{}, nil)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !reflect.DeepEqual(cfg.BPF.AttachPrefixes, []string{"tap"}) {
		t.Errorf("default AttachPrefixes = %v, want [tap]", cfg.BPF.AttachPrefixes)
	}
}

func TestLoadUnsafeAllowUnpinnedMaps(t *testing.T) {
	clearEnv(t)
	// Default is strict (false).
	cfg, err := config.Load(config.Options{}, nil)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.BPF.UnsafeAllowUnpinnedMaps {
		t.Errorf("default UnsafeAllowUnpinnedMaps = true, want false (strict)")
	}

	// Env sets it true (accepts YAML-style "yes" like the other bools).
	clearEnv(t)
	t.Setenv("LACHESIS_BPF_UNSAFE_ALLOW_UNPINNED_MAPS", "true")
	cfg, err = config.Load(config.Options{}, nil)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.BPF.UnsafeAllowUnpinnedMaps {
		t.Errorf("env-set UnsafeAllowUnpinnedMaps = false, want true")
	}

	// Flag wins over env.
	clearEnv(t)
	t.Setenv("LACHESIS_BPF_UNSAFE_ALLOW_UNPINNED_MAPS", "false")
	cfg, err = config.Load(config.Options{}, []string{"-unsafe-allow-unpinned-maps"})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.BPF.UnsafeAllowUnpinnedMaps {
		t.Errorf("flag should win: UnsafeAllowUnpinnedMaps = false, want true")
	}
}

// clearEnv removes any LACHESIS_* env vars set by the host or earlier tests
// so each test sees a clean slate.
func clearEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"LACHESIS_CONFIG",
		"LACHESIS_HTTP_LISTEN",
		"LACHESIS_BPF_PIN_PATH",
		"LACHESIS_BPF_ATTACH_PREFIXES",
		"LACHESIS_BPF_ATTACH_INTERFACES",
		"LACHESIS_BPF_UNSAFE_ALLOW_UNPINNED_MAPS",
		"LACHESIS_SCRAPE_INTERVAL",
		"LACHESIS_LOG_LEVEL",
		"LACHESIS_LOG_FORMAT",
		"LACHESIS_NEUTRON_ENABLED",
		"LACHESIS_NEUTRON_CREDENTIALS_FILE",
	} {
		t.Setenv(k, "")
	}
}

// writeYAML writes content to a temp file and returns its path.
func writeYAML(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write yaml: %v", err)
	}
	return path
}
