//go:build linux

package loadtest

import (
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

// agentTermGrace is how long stopAgent waits between SIGTERM and
// SIGKILL. The agent's own shutdown budget is bounded by its
// internal HTTP + scraper drain (~5s in production); this gives it
// a bit longer to exit cleanly before we kill the process group.
const agentTermGrace = 3 * time.Second

// agentReadyPoll is the inter-poll sleep waitForAgent uses while
// the /metrics endpoint is still warming up. Short enough that the
// harness's effective startup latency is sub-second.
const agentReadyPoll = 100 * time.Millisecond

// writeAgentConfig writes a minimal YAML config that points the
// agent at the host-side veth and asks for an ephemeral listener.
// Returns the path; caller is responsible for os.Remove.
func writeAgentConfig(iface, httpAddr string) (string, error) {
	body := fmt.Sprintf(`version: "1"
http:
  listen: %q
bpf:
  pin_path: /sys/fs/bpf/cubecos-loadtest
  attach_interface: %q
scrape:
  interval: 1s
logging:
  level: warn
  format: text
wal:
  enabled: false
`, httpAddr, iface)
	dir, err := os.MkdirTemp("", "cubecos-loadtest-")
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, "agent.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		return "", err
	}
	return path, nil
}

// startAgent forks the agent binary with -config pointing at path.
// Stdout / stderr go to the loadtest's own streams so failures are
// visible in CI logs.
func startAgent(bin, cfgPath string) (*exec.Cmd, error) {
	cmd := exec.Command(bin, "-config", cfgPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	// New process group so we can deliver signals to the agent only,
	// not the loadtest's own children later.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return cmd, nil
}

// stopAgent sends SIGTERM, waits up to [agentTermGrace] for clean
// shutdown, then SIGKILLs if the agent is unresponsive.
func stopAgent(cmd *exec.Cmd) {
	if cmd.Process == nil {
		return
	}
	_ = cmd.Process.Signal(syscall.SIGTERM)
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(agentTermGrace):
		_ = cmd.Process.Kill()
		<-done
	}
}

// waitForAgent polls /metrics until 200 OK or the deadline elapses.
func waitForAgent(addr string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := http.Get("http://" + addr + "/metrics")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		time.Sleep(agentReadyPoll)
	}
	return fmt.Errorf("/metrics not ready at http://%s within %s", addr, timeout)
}
