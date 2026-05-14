//go:build linux

package loadtest

import (
	"fmt"
	"net"
	"os"
	"os/exec"

	"github.com/vishvananda/netlink"

	tns "github.com/bigstack-oss/cube-cos-network-telemetry/internal/testenv/netns"
)

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
func setupEnv(cfg Config) (*env, error) {
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

	e.cfgPath, err = writeAgentConfig(e.host.Attrs().Name, cfg.HTTPAddr)
	if err != nil {
		return nil, fmt.Errorf("write agent config: %w", err)
	}

	e.agent, err = startAgent(cfg.AgentBin, e.cfgPath)
	if err != nil {
		return nil, fmt.Errorf("start agent: %w", err)
	}

	sinkAddr, stopSink := serveSink()
	e.stopSink = stopSink
	e.sinkPort = uint16(sinkAddr.(*net.TCPAddr).Port)

	ok = true
	return e, nil
}
