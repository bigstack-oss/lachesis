//go:build linux

// Command loadtest exercises the CubeCOS network-telemetry agent
// under sustained TCP traffic and verifies the agent process stays
// inside its resource budget (RSS, CPU). The real harness lives in
// [internal/loadtest]; main is flag parsing + exit codes.
package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/loadtest"
)

func main() {
	cfg := parseFlags()
	if err := loadtest.Run(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "loadtest: %v\n", err)
		os.Exit(1)
	}
}

func parseFlags() loadtest.Config {
	var cfg loadtest.Config
	flag.StringVar(&cfg.AgentBin, "agent", "./build/agent",
		"path to the telemetry agent binary")
	flag.DurationVar(&cfg.Duration, "duration", 15*time.Second,
		"load-generation window")
	flag.IntVar(&cfg.Workers, "workers", 4,
		"concurrent TCP-stream workers")
	flag.Uint64Var(&cfg.RSSLimitMB, "rss-mb", 250,
		"max permitted VmRSS in MB; loadtest fails above this")
	flag.Float64Var(&cfg.CPULimitPct, "cpu-pct", 1.0,
		"max permitted average CPU% over the window")
	flag.StringVar(&cfg.HTTPAddr, "agent-http", "127.0.0.1:19090",
		"address the agent should listen on")
	flag.Parse()
	return cfg
}
