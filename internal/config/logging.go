package config

import "fmt"

// LoggingConfig groups settings for the logging subsystem.
type LoggingConfig struct {
	// Level is the minimum severity emitted. One of: debug, info, warn,
	// error. Hot-reloadable via SIGHUP and the /debug/log-level endpoint.
	Level string `yaml:"level"`
	// Format selects the output encoder. One of: json, text.
	// Load-time; restart required to change.
	Format string `yaml:"format"`
}

func loggingDefaults() LoggingConfig {
	return LoggingConfig{
		Level:  "info",
		Format: "json",
	}
}

// Validate checks the level and format are recognized values.
func (c LoggingConfig) Validate() error {
	switch c.Level {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("level %q not in {debug, info, warn, error}", c.Level)
	}
	switch c.Format {
	case "json", "text":
	default:
		return fmt.Errorf("format %q not in {json, text}", c.Format)
	}
	return nil
}
