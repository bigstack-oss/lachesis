//go:build linux

// Command loadtest exercises the CubeCOS network-telemetry agent
// under sustained TCP traffic and verifies the agent process stays
// inside its resource budget (RSS, CPU).
//
// Topology:
//
//	netns(vm0, 10.77.7.1/30)  <-->  host(tap0, 10.77.7.2/30) [agent attached here]
//	                                       ^
//	                                       |   TCP sink in caller's netns
//
// main is flag parsing + delegate; the test is staged as
// [setupEnv] → [driveLoad] → [report]. Resources owned by [env]
// are released in reverse setup order by [env.Close].
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf/rlimit"
	"github.com/vishvananda/netlink"

	tns "github.com/bigstack-oss/cube-cos-network-telemetry/internal/testenv/netns"
)

// flags bundles the parsed CLI inputs so phase functions take one
// argument instead of six.
type flags struct {
	agentBin    string
	duration    time.Duration
	workers     int
	rssLimitMB  uint64
	cpuLimitPct float64
	httpAddr    string
}

func main() {
	f := parseFlags()
	if err := run(f); err != nil {
		fmt.Fprintf(os.Stderr, "loadtest: %v\n", err)
		os.Exit(1)
	}
}

func parseFlags() flags {
	var f flags
	flag.StringVar(&f.agentBin, "agent", "./build/agent", "path to the telemetry agent binary")
	flag.DurationVar(&f.duration, "duration", 15*time.Second, "load-generation window")
	flag.IntVar(&f.workers, "workers", 4, "concurrent TCP-stream workers")
	flag.Uint64Var(&f.rssLimitMB, "rss-mb", 250, "max permitted VmRSS in MB; loadtest fails above this")
	flag.Float64Var(&f.cpuLimitPct, "cpu-pct", 1.0, "max permitted average CPU% over the window")
	flag.StringVar(&f.httpAddr, "agent-http", "127.0.0.1:19090", "address the agent should listen on")
	flag.Parse()
	return f
}

func run(f flags) error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock: %w", err)
	}

	e, err := setupEnv(f)
	if err != nil {
		return err
	}
	defer e.Close()

	if err := waitForAgent(f.httpAddr, 10*time.Second); err != nil {
		return fmt.Errorf("agent did not become ready: %w", err)
	}
	fmt.Printf("loadtest: agent pid=%d, http=%s\n", e.agent.Process.Pid, f.httpAddr)

	r, err := driveLoad(f, e)
	if err != nil {
		return err
	}
	return report(f, r)
}

// env bundles the agent under test plus its surrounding plumbing —
// netns, veth, on-disk config, subprocess, TCP sink — so phase
// functions accept one handle. [env.Close] releases everything in
// reverse setup order.
type env struct {
	ns       *tns.NS
	host     netlink.Link
	cfgPath  string
	agent    *exec.Cmd
	stopSink func()
	sinkPort uint16
	outerIP  net.IP
}

// Close releases env resources. Safe to call on a partially-built
// env; nil fields are skipped.
func (e *env) Close() {
	if e.agent != nil {
		stopAgent(e.agent)
	}
	if e.stopSink != nil {
		e.stopSink()
	}
	if e.host != nil {
		_ = netlink.LinkDel(e.host)
	}
	if e.ns != nil {
		_ = e.ns.Close()
	}
	if e.cfgPath != "" {
		_ = os.Remove(e.cfgPath)
	}
}

// setupEnv brings up the netns + veth, writes a temporary agent
// config, spawns the agent subprocess, and starts the discarding
// TCP sink. On any failure partial state is cleaned up before the
// error is returned.
func setupEnv(f flags) (*env, error) {
	e := &env{}
	ok := false
	defer func() {
		if !ok {
			e.Close()
		}
	}()

	var err error
	e.ns, err = tns.New()
	if err != nil {
		return nil, fmt.Errorf("new netns: %w", err)
	}

	innerMAC, _ := net.ParseMAC("aa:bb:cc:dd:ee:01")
	outerMAC, _ := net.ParseMAC("aa:bb:cc:dd:ee:02")
	innerIP := &net.IPNet{IP: net.IPv4(10, 77, 7, 1), Mask: net.CIDRMask(30, 32)}
	outerIP := &net.IPNet{IP: net.IPv4(10, 77, 7, 2), Mask: net.CIDRMask(30, 32)}

	e.host, err = e.ns.AddVeth(tns.VethSpec{
		InnerName: "vm-load", OuterName: "tap-load",
		InnerMAC: innerMAC, OuterMAC: outerMAC,
		InnerIP: innerIP, OuterIP: outerIP,
	})
	if err != nil {
		return nil, fmt.Errorf("add veth: %w", err)
	}
	e.outerIP = outerIP.IP

	e.cfgPath, err = writeAgentConfig(e.host.Attrs().Name, f.httpAddr)
	if err != nil {
		return nil, fmt.Errorf("write agent config: %w", err)
	}

	e.agent, err = startAgent(f.agentBin, e.cfgPath)
	if err != nil {
		return nil, fmt.Errorf("start agent: %w", err)
	}

	sinkAddr, stopSink := serveSink()
	e.stopSink = stopSink
	e.sinkPort = uint16(sinkAddr.(*net.TCPAddr).Port)

	ok = true
	return e, nil
}

// result holds the measurements driveLoad emits.
type result struct {
	rssPeakKB uint64
	cpuAvgPct float64
	bytesObs  uint64
}

// driveLoad runs f.workers concurrent TCP workers for f.duration
// while sampling /proc/<agent>/{stat,status} once per second, then
// scrapes /metrics once for the bytes-observed liveness number.
func driveLoad(f flags, e *env) (result, error) {
	first, err := sampleProc(e.agent.Process.Pid)
	if err != nil {
		return result{}, fmt.Errorf("initial sample: %w", err)
	}

	loadCtx, cancel := context.WithTimeout(context.Background(), f.duration)
	defer cancel()

	var wg sync.WaitGroup
	for i := 0; i < f.workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := sustainedTCPSend(loadCtx, e.ns, e.outerIP, e.sinkPort); err != nil && loadCtx.Err() == nil {
				fmt.Fprintf(os.Stderr, "loadtest: worker exited: %v\n", err)
			}
		}()
	}

	rssPeakKB, cpuAvgPct := sampleWindow(e.agent.Process.Pid, loadCtx, time.Second, first)
	wg.Wait()

	bytesObs, err := sumBytesTotal(f.httpAddr)
	if err != nil {
		return result{}, fmt.Errorf("read final /metrics: %w", err)
	}
	return result{rssPeakKB: rssPeakKB, cpuAvgPct: cpuAvgPct, bytesObs: bytesObs}, nil
}

// report prints the verdict and returns a non-nil error if any
// threshold was exceeded. The minBytes guard catches the "BPF never
// fired" failure mode — without it a misconfigured attach can
// silently pass the resource budget.
func report(f flags, r result) error {
	const minBytes uint64 = 1 << 20

	rssPeakMB := r.rssPeakKB / 1024
	pass := rssPeakMB < f.rssLimitMB && r.cpuAvgPct < f.cpuLimitPct && r.bytesObs >= minBytes
	verdict := "PASS"
	if !pass {
		verdict = "FAIL"
	}

	fmt.Printf("\nloadtest: %s\n", verdict)
	fmt.Printf("  duration:        %s\n", f.duration)
	fmt.Printf("  workers:         %d\n", f.workers)
	fmt.Printf("  RSS peak:        %d MB (limit %d MB)\n", rssPeakMB, f.rssLimitMB)
	fmt.Printf("  CPU avg:         %.2f%% (limit %.2f%%)\n", r.cpuAvgPct, f.cpuLimitPct)
	fmt.Printf("  bytes observed:  %d (min %d)\n", r.bytesObs, minBytes)

	if !pass {
		return errors.New("loadtest assertions failed")
	}
	return nil
}

// --- helpers below ---------------------------------------------------------

// sumBytesTotal fetches /metrics once and returns the sum of every
// cubecos_bytes_total sample. Used as a liveness check that the BPF
// program actually saw the load-generated traffic.
func sumBytesTotal(httpAddr string) (uint64, error) {
	resp, err := http.Get("http://" + httpAddr + "/metrics")
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, err
	}
	re := regexp.MustCompile(`cubecos_bytes_total\{[^}]*\} (\d+(?:\.\d+e\+?\d+)?)`)
	var total uint64
	for _, m := range re.FindAllStringSubmatch(string(b), -1) {
		f, err := strconv.ParseFloat(m[1], 64)
		if err != nil {
			continue
		}
		total += uint64(f)
	}
	return total, nil
}

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

// stopAgent sends SIGTERM, waits up to 3s for clean shutdown, then
// SIGKILLs if the agent is unresponsive.
func stopAgent(cmd *exec.Cmd) {
	if cmd.Process == nil {
		return
	}
	_ = cmd.Process.Signal(syscall.SIGTERM)
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
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
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("/metrics not ready at http://%s within %s", addr, timeout)
}

// serveSink starts a discarding TCP listener. Unlike traffic.ServeTCPSink
// (which is *testing.T-coupled) this version is bare so a non-test
// command can use it.
func serveSink() (net.Addr, func()) {
	ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		panic(fmt.Errorf("loadtest: listen: %w", err))
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(io.Discard, conn)
			}(c)
		}
	}()
	return ln.Addr(), func() { _ = ln.Close() }
}

// sustainedTCPSend opens one long-lived TCP connection from inside ns
// and writes 64 KB chunks back-to-back until ctx is cancelled. Using
// a single connection per worker (vs. dial-write-close per iteration)
// avoids ephemeral-port exhaustion during a long load window — the
// kernel's TIME_WAIT pool fills up in seconds at our rate otherwise.
func sustainedTCPSend(ctx context.Context, src *tns.NS, dstIP net.IP, dstPort uint16) error {
	dst := net.JoinHostPort(dstIP.String(), strconv.Itoa(int(dstPort)))
	return src.Do(func() error {
		d := &net.Dialer{Timeout: 5 * time.Second}
		conn, err := d.DialContext(ctx, "tcp", dst)
		if err != nil {
			return fmt.Errorf("loadtest: dial %s: %w", dst, err)
		}
		defer conn.Close()
		buf := make([]byte, 64*1024)
		for ctx.Err() == nil {
			if _, err := conn.Write(buf); err != nil {
				// Sink shutdown is the expected end-of-window path.
				if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
					return nil
				}
				return fmt.Errorf("loadtest: write: %w", err)
			}
		}
		return nil
	})
}

// sampleWindow polls the agent's /proc every interval until ctx is
// cancelled, then returns the peak VmRSS (kB) and average CPU% over
// the whole window. start is the pre-load baseline used to compute
// the integrated CPU%.
func sampleWindow(pid int, ctx context.Context, interval time.Duration, start procSample) (uint64, float64) {
	var (
		rssPeak uint64
		prev    = start
		last    = start
	)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			final, err := sampleProc(pid)
			if err == nil {
				if final.rssKB > rssPeak {
					rssPeak = final.rssKB
				}
				last = final
			}
			return rssPeak, cpuPercent(start, last)
		case <-t.C:
			s, err := sampleProc(pid)
			if err != nil {
				// Process may have exited; surface to caller via stderr.
				fmt.Fprintf(os.Stderr, "loadtest: sample failed: %v\n", err)
				return rssPeak, cpuPercent(start, prev)
			}
			if s.rssKB > rssPeak {
				rssPeak = s.rssKB
			}
			prev = s
			last = s
		}
	}
}
