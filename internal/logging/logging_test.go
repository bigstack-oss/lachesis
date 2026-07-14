package logging_test

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/bigstack-oss/lachesis/internal/config"
	"github.com/bigstack-oss/lachesis/internal/logging"
)

func TestInit_JSONFormat(t *testing.T) {
	var buf bytes.Buffer
	h, err := logging.Init(config.LoggingConfig{Level: "info", Format: "json"}, &buf)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	h.Logger().Info("hello", "key", "value")

	var got map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, buf.String())
	}
	if got["msg"] != "hello" {
		t.Errorf("msg = %v, want hello", got["msg"])
	}
	if got["key"] != "value" {
		t.Errorf("key = %v, want value", got["key"])
	}
	if got["level"] != "INFO" {
		t.Errorf("level = %v, want INFO", got["level"])
	}
}

func TestInit_TextFormat(t *testing.T) {
	var buf bytes.Buffer
	h, err := logging.Init(config.LoggingConfig{Level: "info", Format: "text"}, &buf)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	h.Logger().Info("hello", "key", "value")

	if !strings.Contains(buf.String(), "msg=hello") {
		t.Errorf("text output missing msg=hello: %s", buf.String())
	}
}

func TestInit_BadLevel(t *testing.T) {
	if _, err := logging.Init(config.LoggingConfig{Level: "verbose", Format: "json"}, &bytes.Buffer{}); err == nil {
		t.Fatal("expected error for invalid level")
	}
}

func TestInit_BadFormat(t *testing.T) {
	if _, err := logging.Init(config.LoggingConfig{Level: "info", Format: "xml"}, &bytes.Buffer{}); err == nil {
		t.Fatal("expected error for invalid format")
	}
}

func TestInit_DefaultLoggerInstalled(t *testing.T) {
	var buf bytes.Buffer
	_, err := logging.Init(config.LoggingConfig{Level: "info", Format: "json"}, &buf)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	// slog.Default should route through our handler now.
	slog.Info("via default")
	if !strings.Contains(buf.String(), "via default") {
		t.Errorf("slog.Default not installed: %s", buf.String())
	}
}

func TestSetLevel_FiltersAtRuntime(t *testing.T) {
	var buf bytes.Buffer
	h, err := logging.Init(config.LoggingConfig{Level: "info", Format: "json"}, &buf)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}

	// At info, Debug should be filtered.
	h.Logger().Debug("filtered")
	if strings.Contains(buf.String(), "filtered") {
		t.Errorf("Debug should not appear at info level: %s", buf.String())
	}

	// Promote to debug — now it should appear.
	if err := h.SetLevel("debug"); err != nil {
		t.Fatalf("SetLevel: %v", err)
	}
	buf.Reset()
	h.Logger().Debug("now visible")
	if !strings.Contains(buf.String(), "now visible") {
		t.Errorf("Debug should appear after SetLevel(debug): %s", buf.String())
	}

	// Demote back to warn — info should also be filtered.
	if err := h.SetLevel("warn"); err != nil {
		t.Fatalf("SetLevel: %v", err)
	}
	buf.Reset()
	h.Logger().Info("filtered too")
	if strings.Contains(buf.String(), "filtered too") {
		t.Errorf("Info should not appear at warn level: %s", buf.String())
	}
}

func TestSetLevel_BadValue(t *testing.T) {
	h, _ := logging.Init(config.LoggingConfig{Level: "info", Format: "json"}, &bytes.Buffer{})
	if err := h.SetLevel("verbose"); err == nil {
		t.Fatal("expected error for invalid level")
	}
}

func TestCurrentLevel(t *testing.T) {
	h, _ := logging.Init(config.LoggingConfig{Level: "info", Format: "json"}, &bytes.Buffer{})
	if got := h.CurrentLevel(); got != "info" {
		t.Errorf("CurrentLevel = %q, want info", got)
	}
	_ = h.SetLevel("warn")
	if got := h.CurrentLevel(); got != "warn" {
		t.Errorf("CurrentLevel = %q, want warn", got)
	}
}

func TestParseLevel(t *testing.T) {
	cases := []struct {
		in   string
		want slog.Level
	}{
		{"debug", slog.LevelDebug},
		{"info", slog.LevelInfo},
		{"warn", slog.LevelWarn},
		{"error", slog.LevelError},
		{"INFO", slog.LevelInfo}, // case-insensitive
		{"Debug", slog.LevelDebug},
	}
	for _, c := range cases {
		got, err := logging.ParseLevel(c.in)
		if err != nil {
			t.Errorf("ParseLevel(%q) error: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("ParseLevel(%q) = %v, want %v", c.in, got, c.want)
		}
	}

	if _, err := logging.ParseLevel("verbose"); err == nil {
		t.Errorf("expected error for verbose")
	}
}
