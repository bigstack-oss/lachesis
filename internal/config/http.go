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
