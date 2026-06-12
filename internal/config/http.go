package config

import (
	"errors"
	"fmt"
	"net"
)

// HTTPConfig groups settings for the agent's HTTP server, which serves
// the Prometheus /metrics endpoint and the /debug runtime-tuning
// endpoints.
type HTTPConfig struct {
	// Listen is the address to bind, in net.Listen syntax (host:port).
	//
	// The default ":9090" binds all interfaces so Prometheus can scrape
	// /metrics, and the server is unauthenticated — including the
	// /debug endpoints (pprof, runtime tuning; secrets are redacted
	// from /debug/config). On untrusted networks, bind to localhost
	// (e.g. "127.0.0.1:9090") or firewall the port.
	Listen string `yaml:"listen"`
}

func httpDefaults() HTTPConfig {
	return HTTPConfig{
		Listen: ":9090",
	}
}

// Validate checks the listen address is a parseable host:port.
func (c HTTPConfig) Validate() error {
	if c.Listen == "" {
		return errors.New("listen address is empty")
	}
	if _, _, err := net.SplitHostPort(c.Listen); err != nil {
		return fmt.Errorf("listen %q: %w", c.Listen, err)
	}
	return nil
}
