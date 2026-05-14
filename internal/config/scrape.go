package config

import (
	"fmt"
	"time"
)

// ScrapeConfig groups settings for the BPF map scraper.
type ScrapeConfig struct {
	// Interval is the cadence at which the scraper drains the BPF map
	// and applies deltas to GlobalState. Minimum 1 second.
	Interval time.Duration `yaml:"interval"`
}

func scrapeDefaults() ScrapeConfig {
	return ScrapeConfig{
		Interval: 10 * time.Second,
	}
}

// Validate ensures the scrape interval is at least one second.
// Sub-second scraping isn't useful at our timescale and amplifies
// bench-gate noise.
func (c ScrapeConfig) Validate() error {
	if c.Interval < time.Second {
		return fmt.Errorf("interval %v is too small (minimum 1s)", c.Interval)
	}
	return nil
}
