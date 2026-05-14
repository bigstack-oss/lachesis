package agent_test

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/agent"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/bpf"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/config"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/logging"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/scraper"
)

// staticReader returns a fixed snapshot on every BatchLookup; suitable
// for asserting that the agent's wiring delivers state to /metrics
// without needing a real BPF map.
type staticReader struct {
	entries map[bpf.FlowKey]bpf.FlowMetrics
	calls   atomic.Uint64
}

func (s *staticReader) BatchLookup(dst map[bpf.FlowKey]bpf.FlowMetrics) error {
	s.calls.Add(1)
	for k, v := range s.entries {
		dst[k] = v
	}
	return nil
}

func newTestApp(t *testing.T, reader scraper.MapReader) (*agent.App, context.CancelFunc) {
	t.Helper()
	cfg := config.Defaults()
	cfg.HTTP.Listen = "127.0.0.1:0" // ephemeral
	cfg.Scrape.Interval = 25 * time.Millisecond
	log, err := logging.Init(cfg.Logging, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("logging.Init: %v", err)
	}
	app, err := agent.New(agent.Options{
		Config: cfg,
		Reader: reader,
		Log:    log,
	})
	if err != nil {
		t.Fatalf("agent.New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_ = app.Run(ctx)
		close(done)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Errorf("agent did not exit within 2s of cancel")
		}
	})
	return app, cancel
}

func TestApp_ServesMetricsFromReader(t *testing.T) {
	reader := &staticReader{
		entries: map[bpf.FlowKey]bpf.FlowMetrics{
			{
				SrcMac:    [6]uint8{0xaa, 0, 0, 0, 0, 1},
				DstMac:    [6]uint8{0xaa, 0, 0, 0, 0, 2},
				EthProto:  0x0800,
				Direction: bpf.DirectionEgress,
				DstZone:   bpf.ZoneExternal,
			}: {Bytes: 4242, Packets: 7, LastSeenNs: 1},
		},
	}
	app, _ := newTestApp(t, reader)

	// Poll up to 1s for the first scrape to complete and surface in /metrics.
	body := mustGetMetrics(t, app.Addr(), time.Second, func(s string) bool {
		return strings.Contains(s, `cubecos_bytes_total{direction="egress",tenant_id="unknown",zone="external"} 4242`)
	})

	for _, want := range []string{
		`cubecos_bytes_total{direction="egress",tenant_id="unknown",zone="external"} 4242`,
		`cubecos_packets_total{direction="egress",tenant_id="unknown",zone="external"} 7`,
		`cubecos_state_flows 1`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q\n----\n%s", want, body)
		}
	}
}

func TestApp_DebugConfigEndpoint(t *testing.T) {
	reader := &staticReader{entries: map[bpf.FlowKey]bpf.FlowMetrics{}}
	app, _ := newTestApp(t, reader)

	// Give the listener a moment to be ready.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get("http://" + app.Addr() + "/debug/config")
		if err == nil && resp.StatusCode == http.StatusOK {
			resp.Body.Close()
			return
		}
		if resp != nil {
			resp.Body.Close()
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("/debug/config did not return 200 within 1s")
}

func TestApp_NilReaderRejected(t *testing.T) {
	cfg := config.Defaults()
	cfg.HTTP.Listen = "127.0.0.1:0"
	log, _ := logging.Init(cfg.Logging, &bytes.Buffer{})
	_, err := agent.New(agent.Options{Config: cfg, Log: log})
	if err == nil {
		t.Fatal("agent.New with nil Reader should fail")
	}
}

// blockingReader holds BatchLookup until Release is closed. It also
// signals the first call so tests can observe the scraper entering
// the (blocked) Tick.
type blockingReader struct {
	inflight chan struct{} // buffered 1; receives a signal on first call
	release  chan struct{} // close to let pending and future calls return
}

func (b *blockingReader) BatchLookup(_ map[bpf.FlowKey]bpf.FlowMetrics) error {
	select {
	case b.inflight <- struct{}{}:
	default: // already signalled; subsequent calls don't re-signal
	}
	<-b.release
	return nil
}

// TestApp_ShutdownWaitsForScraper verifies that App.Run does not
// return while the scraper is still inside a Tick (i.e. mid
// BatchLookup). Without this guarantee, callers that close BPF
// resources after Run returns can race the kernel-map read.
func TestApp_ShutdownWaitsForScraper(t *testing.T) {
	r := &blockingReader{
		inflight: make(chan struct{}, 1),
		release:  make(chan struct{}),
	}
	cfg := config.Defaults()
	cfg.HTTP.Listen = "127.0.0.1:0"
	cfg.Scrape.Interval = 25 * time.Millisecond
	log, err := logging.Init(cfg.Logging, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("logging.Init: %v", err)
	}
	app, err := agent.New(agent.Options{Config: cfg, Reader: r, Log: log})
	if err != nil {
		t.Fatalf("agent.New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan struct{})
	go func() {
		_ = app.Run(ctx)
		close(runDone)
	}()

	// Wait for the first BatchLookup to begin.
	select {
	case <-r.inflight:
	case <-time.After(time.Second):
		t.Fatal("scraper did not reach BatchLookup within 1s")
	}

	// Trigger shutdown. Run must NOT return yet — the scraper is
	// still blocked inside BatchLookup.
	cancel()
	select {
	case <-runDone:
		t.Fatal("Run returned while scraper was still inside BatchLookup")
	case <-time.After(150 * time.Millisecond):
		// Expected: Run is still blocked waiting for the scraper.
	}

	// Release the scraper; Run should now drain and return.
	close(r.release)
	select {
	case <-runDone:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return within 2s of scraper release")
	}
}

// mustGetMetrics polls /metrics until predicate matches or deadline
// elapses. Returns the last body seen.
func mustGetMetrics(t *testing.T, addr string, timeout time.Duration, predicate func(string) bool) string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var lastBody string
	for time.Now().Before(deadline) {
		resp, err := http.Get("http://" + addr + "/metrics")
		if err != nil {
			time.Sleep(10 * time.Millisecond)
			continue
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		lastBody = string(b)
		if predicate(lastBody) {
			return lastBody
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("predicate not satisfied within %s; last body:\n%s", timeout, lastBody)
	return lastBody
}
