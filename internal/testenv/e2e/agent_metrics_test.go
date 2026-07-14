//go:build integration

package e2e_test

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/vishvananda/netlink"

	"github.com/bigstack-oss/lachesis/internal/agent"
	"github.com/bigstack-oss/lachesis/internal/bpf"
	"github.com/bigstack-oss/lachesis/internal/config"
	"github.com/bigstack-oss/lachesis/internal/logging"
	tns "github.com/bigstack-oss/lachesis/internal/testenv/netns"
	"github.com/bigstack-oss/lachesis/internal/testenv/traffic"
)

// TestAgent_MetricsReflectBPFMapTraffic exercises the L3↔L4 spine
// end to end: load the real telemetry collection, attach it to a
// host-side veth, run the agent in-process pointed at the same map,
// generate a 1 MB TCP stream, then assert that /metrics surfaces a
// non-zero cubecos_bytes_total.
//
// Topology mirrors TestE2E_SingleVM_NoopCounter; the difference is
// the program loaded (telemetry, not noop) and the assertion target
// (Prometheus /metrics, not a raw counter map).
func TestAgent_MetricsReflectBPFMapTraffic(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("rlimit: %v", err)
	}

	spec, err := bpf.LoadTelemetry()
	if err != nil {
		t.Fatalf("load telemetry spec: %v", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatalf("NewCollection: %v", err)
	}
	defer coll.Close()

	ns, err := tns.New()
	if err != nil {
		t.Fatalf("netns: %v", err)
	}
	defer ns.Close()

	innerMAC, _ := net.ParseMAC("aa:bb:cc:dd:e3:01")
	outerMAC, _ := net.ParseMAC("aa:bb:cc:dd:e3:02")
	innerIP := &net.IPNet{IP: net.IPv4(10, 88, 0, 1), Mask: net.CIDRMask(30, 32)}
	outerIP := &net.IPNet{IP: net.IPv4(10, 88, 0, 2), Mask: net.CIDRMask(30, 32)}

	host, err := ns.AddVeth(tns.VethSpec{
		InnerName: "vm-agt", OuterName: "tap-agt",
		InnerMAC: innerMAC, OuterMAC: outerMAC,
		InnerIP: innerIP, OuterIP: outerIP,
	})
	if err != nil {
		t.Fatalf("AddVeth: %v", err)
	}
	defer netlink.LinkDel(host)

	ingress := coll.Programs[bpf.ProgramIngress]
	egress := coll.Programs[bpf.ProgramEgress]
	if ingress == nil || egress == nil {
		t.Fatalf("telemetry collection missing %s or %s",
			bpf.ProgramIngress, bpf.ProgramEgress)
	}
	if err := tns.AttachBPF(host, ingress, tns.TCIngress, "tel_in"); err != nil {
		t.Fatalf("attach ingress: %v", err)
	}
	if err := tns.AttachBPF(host, egress, tns.TCEgress, "tel_out"); err != nil {
		t.Fatalf("attach egress: %v", err)
	}

	reader, err := agent.NewBPFMapReader(coll.Maps[bpf.MapTelemetry])
	if err != nil {
		t.Fatalf("NewBPFMapReader: %v", err)
	}

	cfg := config.Defaults()
	cfg.HTTP.Listen = "127.0.0.1:0"
	cfg.Scrape.Interval = 100 * time.Millisecond
	log, err := logging.Init(cfg.Logging, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("logging.Init: %v", err)
	}
	ag, err := agent.New(agent.Options{Config: cfg, Reader: reader, Log: log})
	if err != nil {
		t.Fatalf("agent.New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_ = ag.Run(ctx)
		close(done)
	}()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("agent did not exit within 2s of cancel")
		}
	}()

	addr, stop := traffic.ServeTCPSink(t)
	defer stop()
	tcpAddr := addr.(*net.TCPAddr)
	const payload = 1 * 1024 * 1024
	if err := traffic.SendTCPStream(ns, outerIP.IP, uint16(tcpAddr.Port), payload); err != nil {
		t.Fatalf("send: %v", err)
	}

	bytesTotalRe := regexp.MustCompile(`cubecos_bytes_total\{[^}]*\} (\d+)`)
	deadline := time.Now().Add(3 * time.Second)
	var lastBody string
	for time.Now().Before(deadline) {
		resp, err := http.Get("http://" + ag.Addr() + "/metrics")
		if err != nil {
			time.Sleep(50 * time.Millisecond)
			continue
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		lastBody = string(b)
		for _, m := range bytesTotalRe.FindAllStringSubmatch(lastBody, -1) {
			v, _ := strconv.ParseUint(m[1], 10, 64)
			if v > 0 {
				t.Logf("observed metric: %s = %d", m[0], v)
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("no non-zero cubecos_bytes_total within 3s\nlast /metrics:\n%s", lastBody)
}
