package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/config"
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

func TestLoadDefaultsOnly(t *testing.T) {
	// No flags, no env, no yaml — should match Defaults().
	clearEnv(t)
	cfg, err := config.Load(config.Options{}, nil)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := config.Defaults()
	if cfg != want {
		t.Errorf("cfg = %+v, want %+v", cfg, want)
	}
}

func TestLoadFromEnv(t *testing.T) {
	clearEnv(t)
	t.Setenv("CUBECOS_HTTP_LISTEN", ":9200")
	t.Setenv("CUBECOS_SCRAPE_INTERVAL", "30s")
	t.Setenv("CUBECOS_LOG_LEVEL", "warn")
	t.Setenv("CUBECOS_LOG_FORMAT", "text")

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
	t.Setenv("CUBECOS_HTTP_LISTEN", ":2222")

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
	t.Setenv("CUBECOS_SCRAPE_INTERVAL", "not-a-duration")
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
		if key == "CUBECOS_HTTP_LISTEN" {
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

func TestLoad_CustomPrefixDoesNotReadCubecos(t *testing.T) {
	clearEnv(t)
	t.Setenv("CUBECOS_HTTP_LISTEN", ":9999")
	getenv := func(key string) string { return os.Getenv(key) }
	cfg, err := config.Load(config.Options{EnvPrefix: "ACME", Getenv: getenv}, nil)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.HTTP.Listen != ":9090" {
		t.Errorf("HTTP.Listen = %q, want :9090 (CUBECOS_ should be ignored under ACME prefix)", cfg.HTTP.Listen)
	}
}

func TestDefaultEnvPrefix(t *testing.T) {
	if config.DefaultEnvPrefix != "CUBECOS" {
		t.Errorf("DefaultEnvPrefix = %q, want CUBECOS", config.DefaultEnvPrefix)
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

// clearEnv removes any CUBECOS_* env vars set by the host or earlier tests
// so each test sees a clean slate.
func clearEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"CUBECOS_CONFIG",
		"CUBECOS_HTTP_LISTEN",
		"CUBECOS_BPF_PIN_PATH",
		"CUBECOS_SCRAPE_INTERVAL",
		"CUBECOS_LOG_LEVEL",
		"CUBECOS_LOG_FORMAT",
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
