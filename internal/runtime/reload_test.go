package runtime_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/config"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/logging"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/runtime"
)

func TestReload_AppliesHotField(t *testing.T) {
	path, initial := setup(t, "info")
	logHandle, err := logging.Init(initial.Logging, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("logging.Init: %v", err)
	}
	mgr := runtime.New(path, initial, logHandle)

	// Update the YAML to bump logging.level to debug.
	writeYAML(t, path, "debug")

	if err := mgr.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	got := mgr.Current().Logging.Level
	if got != "debug" {
		t.Errorf("Current().Logging.Level = %q, want debug", got)
	}
	if got := logHandle.CurrentLevel(); got != "debug" {
		t.Errorf("logger CurrentLevel = %q, want debug", got)
	}
}

func TestReload_RejectsBadYAML(t *testing.T) {
	path, initial := setup(t, "info")
	logHandle, _ := logging.Init(initial.Logging, &bytes.Buffer{})
	mgr := runtime.New(path, initial, logHandle)

	if err := os.WriteFile(path, []byte("not: valid: yaml: at: all"), 0o600); err != nil {
		t.Fatalf("write yaml: %v", err)
	}
	if err := mgr.Reload(); err == nil {
		t.Fatal("expected error from malformed YAML")
	}
	// Original level must be preserved on failure.
	if got := mgr.Current().Logging.Level; got != "info" {
		t.Errorf("Reload should not have changed state: got %q", got)
	}
}

func TestReload_NoConfigFile(t *testing.T) {
	logHandle, _ := logging.Init(config.Defaults().Logging, &bytes.Buffer{})
	mgr := runtime.New("", config.Defaults(), logHandle)
	err := mgr.Reload()
	if err == nil {
		t.Fatal("Reload with empty configPath should error")
	}
	if !strings.Contains(err.Error(), "no config file") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestReload_WarnsOnLoadTimeFieldChange(t *testing.T) {
	var buf bytes.Buffer
	path, initial := setup(t, "info")
	logHandle, _ := logging.Init(initial.Logging, &buf)
	mgr := runtime.New(path, initial, logHandle)

	// Change a load-time field (http.listen) in the YAML.
	updated := `
version: "1"
http:
  listen: ":9999"
bpf:
  pin_path: /sys/fs/bpf/telemetry
scrape:
  interval: 10s
logging:
  level: info
  format: json
`
	if err := os.WriteFile(path, []byte(updated), 0o600); err != nil {
		t.Fatalf("write yaml: %v", err)
	}
	if err := mgr.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	// Snapshot stores the new value, but the running HTTP listener is
	// unchanged — verified by the warning being logged.
	if !strings.Contains(buf.String(), "load-time field change ignored") {
		t.Errorf("expected warning in logs, got: %s", buf.String())
	}
	if !strings.Contains(buf.String(), "http.listen") {
		t.Errorf("warning should name the field, got: %s", buf.String())
	}
}

func TestDebugHandler_GetConfig(t *testing.T) {
	path, initial := setup(t, "info")
	logHandle, _ := logging.Init(initial.Logging, &bytes.Buffer{})
	mgr := runtime.New(path, initial, logHandle)

	req := httptest.NewRequest(http.MethodGet, "/debug/config", nil)
	rec := httptest.NewRecorder()
	mgr.DebugHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var got config.Config
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("body is not JSON: %v\n%s", err, rec.Body.String())
	}
	if got.Logging.Level != "info" {
		t.Errorf("Logging.Level = %q, want info", got.Logging.Level)
	}
}

func TestDebugHandler_GetConfig_RedactsPassword(t *testing.T) {
	const secret = "hunter2-keystone-admin"
	initial := config.Defaults()
	initial.Neutron.Enabled = true
	initial.Neutron.AuthURL = "http://keystone.example:5000/v3"
	initial.Neutron.Username = "admin_cli"
	initial.Neutron.Password = secret
	initial.Neutron.ProjectName = "admin"
	logHandle, _ := logging.Init(initial.Logging, &bytes.Buffer{})
	mgr := runtime.New("", initial, logHandle)

	req := httptest.NewRequest(http.MethodGet, "/debug/config", nil)
	rec := httptest.NewRecorder()
	mgr.DebugHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if strings.Contains(body, secret) {
		t.Errorf("/debug/config leaked the Neutron password:\n%s", body)
	}
	var got config.Config
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("body is not JSON: %v\n%s", err, body)
	}
	if got.Neutron.Password != "***" {
		t.Errorf("Neutron.Password = %q, want \"***\"", got.Neutron.Password)
	}
	// Non-secret fields still come through.
	if got.Neutron.Username != "admin_cli" {
		t.Errorf("Neutron.Username = %q, want admin_cli", got.Neutron.Username)
	}
}

func TestDebugHandler_PutLogLevel(t *testing.T) {
	var buf bytes.Buffer
	path, initial := setup(t, "info")
	logHandle, _ := logging.Init(initial.Logging, &buf)
	mgr := runtime.New(path, initial, logHandle)

	req := httptest.NewRequest(http.MethodPut, "/debug/log-level",
		strings.NewReader(`{"level":"warn"}`))
	rec := httptest.NewRecorder()
	mgr.DebugHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body=%s", rec.Code, rec.Body.String())
	}
	if got := logHandle.CurrentLevel(); got != "warn" {
		t.Errorf("CurrentLevel = %q, want warn", got)
	}
	if got := mgr.Current().Logging.Level; got != "warn" {
		t.Errorf("Current().Logging.Level = %q, want warn", got)
	}
}

func TestDebugHandler_PutLogLevel_BadBody(t *testing.T) {
	logHandle, _ := logging.Init(config.Defaults().Logging, &bytes.Buffer{})
	mgr := runtime.New("", config.Defaults(), logHandle)

	req := httptest.NewRequest(http.MethodPut, "/debug/log-level",
		strings.NewReader(`{"level":"verbose"}`))
	rec := httptest.NewRecorder()
	mgr.DebugHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestDebugHandler_PutLogLevel_OversizedBody(t *testing.T) {
	logHandle, _ := logging.Init(config.Defaults().Logging, &bytes.Buffer{})
	mgr := runtime.New("", config.Defaults(), logHandle)

	// Valid JSON padded past the 1 KiB cap; size alone must reject it.
	huge := `{"level":"debug","pad":"` + strings.Repeat("x", 4096) + `"}`
	req := httptest.NewRequest(http.MethodPut, "/debug/log-level",
		strings.NewReader(huge))
	rec := httptest.NewRecorder()
	mgr.DebugHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want 413", rec.Code)
	}
	if got := logHandle.CurrentLevel(); got != "info" {
		t.Errorf("CurrentLevel = %q, want info (unchanged)", got)
	}
}

func TestInstallSIGHUP_TriggersReload(t *testing.T) {
	path, initial := setup(t, "info")
	logHandle, _ := logging.Init(initial.Logging, &bytes.Buffer{})
	mgr := runtime.New(path, initial, logHandle)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mgr.InstallSIGHUP(ctx)

	// Mutate the YAML and raise SIGHUP at ourselves.
	writeYAML(t, path, "warn")
	if err := syscall.Kill(os.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatalf("kill SIGHUP: %v", err)
	}

	// Poll up to 1s for the level to update.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if logHandle.CurrentLevel() == "warn" {
			return // success
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Errorf("SIGHUP did not trigger reload; level still %q", logHandle.CurrentLevel())
}

// setup writes an initial YAML with the given log level and returns the
// path plus the loaded Config.
func setup(t *testing.T, level string) (string, config.Config) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.yaml")
	writeYAML(t, path, level)
	cfg, err := config.LoadYAML(path)
	if err != nil {
		t.Fatalf("LoadYAML: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	return path, cfg
}

// writeYAML writes a minimal valid YAML with the given log level.
func writeYAML(t *testing.T, path, level string) {
	t.Helper()
	body := `
version: "1"
http:
  listen: ":9090"
bpf:
  pin_path: /sys/fs/bpf/telemetry
scrape:
  interval: 10s
logging:
  level: ` + level + `
  format: json
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write yaml: %v", err)
	}
}
