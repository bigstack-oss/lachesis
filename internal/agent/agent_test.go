package agent_test

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/agent"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/bpf"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/config"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/logging"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/scraper"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/state"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/wal"
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

func newTestAgent(t *testing.T, reader scraper.MapReader) (*agent.Agent, context.CancelFunc) {
	t.Helper()
	return newTestAgentCfg(t, reader, func(cfg *config.Config) {
		// Existing tests don't care about persistence and would
		// otherwise log "final flush failed" against the
		// production WAL path on shutdown.
		cfg.WAL.Enabled = false
	})
}

// newTestAgentCfg constructs and runs a test agent, applying mutate
// after Defaults() so callers can opt into specific config (e.g.
// enable the WAL with a tempdir path).
func newTestAgentCfg(t *testing.T, reader scraper.MapReader, mutate func(*config.Config)) (*agent.Agent, context.CancelFunc) {
	t.Helper()
	cfg := config.Defaults()
	cfg.HTTP.Listen = "127.0.0.1:0" // ephemeral
	cfg.Scrape.Interval = 25 * time.Millisecond
	if mutate != nil {
		mutate(&cfg)
	}
	// cfg.Validate is intentionally skipped — tests use sub-second
	// scrape intervals that the production validator rejects.
	log, err := logging.Init(cfg.Logging, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("logging.Init: %v", err)
	}
	ag, err := agent.New(agent.Options{
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
		_ = ag.Run(ctx)
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
	return ag, cancel
}

func TestAgent_ServesMetricsFromReader(t *testing.T) {
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
	ag, _ := newTestAgent(t, reader)

	// Poll up to 1s for the first scrape to complete and surface in /metrics.
	body := mustGetMetrics(t, ag.Addr(), time.Second, func(s string) bool {
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

func TestAgent_DebugConfigEndpoint(t *testing.T) {
	reader := &staticReader{entries: map[bpf.FlowKey]bpf.FlowMetrics{}}
	ag, _ := newTestAgent(t, reader)

	// Give the listener a moment to be ready.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get("http://" + ag.Addr() + "/debug/config")
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

func TestAgent_NilReaderRejected(t *testing.T) {
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

// TestAgent_ShutdownWaitsForScraper verifies that Agent.Run does not
// return while the scraper is still inside a Tick (i.e. mid
// BatchLookup). Without this guarantee, callers that close BPF
// resources after Run returns can race the kernel-map read.
func TestAgent_ShutdownWaitsForScraper(t *testing.T) {
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
	ag, err := agent.New(agent.Options{Config: cfg, Reader: r, Log: log})
	if err != nil {
		t.Fatalf("agent.New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan struct{})
	go func() {
		_ = ag.Run(ctx)
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

func TestAgent_SeedStateAppearsOnMetrics(t *testing.T) {
	// A reader that returns no entries; without the seed the
	// emitted total would be 0. The Restore-via-SeedState path
	// must show up on /metrics.
	r := &staticReader{entries: map[bpf.FlowKey]bpf.FlowMetrics{}}
	ag, _ := newTestAgent(t, r)

	seeded := []state.Record{{
		Key: bpf.FlowKey{
			SrcMac:    [6]uint8{0xaa, 0, 0, 0, 0, 1},
			DstMac:    [6]uint8{0xaa, 0, 0, 0, 0, 2},
			EthProto:  0x0800,
			Direction: bpf.DirectionEgress,
			DstZone:   bpf.ZoneExternal,
		},
		Counter: state.Counter{
			Total:       bpf.FlowMetrics{Bytes: 7777, Packets: 13, LastSeenNs: 1},
			LastEbpfRaw: bpf.FlowMetrics{Bytes: 7777, Packets: 13, LastSeenNs: 1},
		},
	}}
	ag.SeedState(seeded)

	body := mustGetMetrics(t, ag.Addr(), time.Second, func(s string) bool {
		return strings.Contains(s, `cubecos_bytes_total{direction="egress",tenant_id="unknown",zone="external"} 7777`)
	})
	if !strings.Contains(body, `cubecos_packets_total{direction="egress",tenant_id="unknown",zone="external"} 13`) {
		t.Errorf("packets total missing or wrong; body:\n%s", body)
	}
}

func TestAgent_WALPeriodicFlushWritesSnapshot(t *testing.T) {
	walPath := filepath.Join(t.TempDir(), "wal.json")

	r := &staticReader{entries: map[bpf.FlowKey]bpf.FlowMetrics{
		{
			SrcMac:    [6]uint8{0xaa, 0, 0, 0, 0, 1},
			DstMac:    [6]uint8{0xaa, 0, 0, 0, 0, 2},
			EthProto:  0x0800,
			Direction: bpf.DirectionEgress,
			DstZone:   bpf.ZoneExternal,
		}: {Bytes: 4242, Packets: 7, LastSeenNs: 1},
	}}
	_, _ = newTestAgentCfg(t, r, func(cfg *config.Config) {
		cfg.WAL.Path = walPath
		cfg.WAL.FlushInterval = 50 * time.Millisecond
		cfg.WAL.Enabled = true
	})

	// Wait for the scraper to apply the delta AND the WAL ticker
	// to fire at least once.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		res, err := wal.Load(walPath)
		if err == nil && res.Source == wal.LoadFromPrimary && len(res.Records) > 0 {
			if res.Records[0].Counter.Total.Bytes != 4242 {
				t.Errorf("loaded Total.Bytes = %d, want 4242",
					res.Records[0].Counter.Total.Bytes)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("WAL was not written within 2s with the seeded reader entry")
}

func TestAgent_WALMetricsAppearOnMetricsEndpoint(t *testing.T) {
	walPath := filepath.Join(t.TempDir(), "wal.json")

	r := &staticReader{entries: map[bpf.FlowKey]bpf.FlowMetrics{
		{
			SrcMac:    [6]uint8{0xaa, 0, 0, 0, 0, 1},
			DstMac:    [6]uint8{0xaa, 0, 0, 0, 0, 2},
			EthProto:  0x0800,
			Direction: bpf.DirectionEgress,
			DstZone:   bpf.ZoneExternal,
		}: {Bytes: 1, Packets: 1, LastSeenNs: 1},
	}}
	ag, _ := newTestAgentCfg(t, r, func(cfg *config.Config) {
		cfg.WAL.Path = walPath
		cfg.WAL.FlushInterval = 50 * time.Millisecond
		cfg.WAL.Enabled = true
	})
	// Also record one boot-time load fallback synthetically (Bootstrap
	// would normally do this; agent.New does not).
	ag.WALMetrics().RecordLoadFallback(wal.LoadFallbackEmpty)

	// Wait for at least one flush to populate the histograms.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := wal.Load(walPath); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	body := mustGetMetrics(t, ag.Addr(), time.Second, func(s string) bool {
		return strings.Contains(s, "cubecos_wal_marshal_seconds_count") &&
			strings.Contains(s, "cubecos_wal_flush_latency_seconds_count")
	})

	for _, want := range []string{
		"cubecos_wal_snapshot_copy_seconds_count",
		"cubecos_wal_marshal_seconds_count",
		"cubecos_wal_flush_latency_seconds_count",
		`cubecos_wal_load_fallback_total{from="empty"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("/metrics missing %q\n----\n%s", want, body)
		}
	}
}

func TestAgent_WALFinalFlushOnShutdown(t *testing.T) {
	walPath := filepath.Join(t.TempDir(), "wal.json")

	r := &staticReader{entries: map[bpf.FlowKey]bpf.FlowMetrics{
		{
			SrcMac:    [6]uint8{0xaa, 0, 0, 0, 0, 1},
			DstMac:    [6]uint8{0xaa, 0, 0, 0, 0, 2},
			EthProto:  0x0800,
			Direction: bpf.DirectionEgress,
			DstZone:   bpf.ZoneExternal,
		}: {Bytes: 9999, Packets: 33, LastSeenNs: 1},
	}}

	// Long flush interval so only the shutdown-final-flush has a
	// chance to write. Self-contained lifecycle (no helper) so the
	// WAL assertion ordering is explicit: cancel → wait → assert.
	cfg := config.Defaults()
	cfg.HTTP.Listen = "127.0.0.1:0"
	cfg.Scrape.Interval = 25 * time.Millisecond
	cfg.WAL.Path = walPath
	cfg.WAL.FlushInterval = 30 * time.Second
	cfg.WAL.Enabled = true

	log, err := logging.Init(cfg.Logging, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("logging.Init: %v", err)
	}
	ag, err := agent.New(agent.Options{Config: cfg, Reader: r, Log: log})
	if err != nil {
		t.Fatalf("agent.New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_ = ag.Run(ctx)
		close(done)
	}()

	// Wait for the scraper to absorb the seeded delta at least once.
	time.Sleep(150 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("agent did not exit within 2s of cancel")
	}

	res, err := wal.Load(walPath)
	if err != nil {
		t.Fatalf("wal.Load: %v", err)
	}
	if res.Source != wal.LoadFromPrimary || len(res.Records) == 0 {
		t.Fatalf("final flush did not produce a usable WAL: source=%v records=%d",
			res.Source, len(res.Records))
	}
	if res.Records[0].Counter.Total.Bytes != 9999 {
		t.Errorf("final flush Total.Bytes = %d, want 9999",
			res.Records[0].Counter.Total.Bytes)
	}
}

// TestAgent_WALFinalFlushOnServerError proves H1: when the HTTP server
// fails on its own (here, the listener is closed out from under it),
// Run still drains the workers and runs the WAL final flush rather than
// returning immediately and leaking goroutines. Without the drain on
// the srvErr path, the seeded delta would never reach disk.
func TestAgent_WALFinalFlushOnServerError(t *testing.T) {
	walPath := filepath.Join(t.TempDir(), "wal.json")

	r := &staticReader{entries: map[bpf.FlowKey]bpf.FlowMetrics{
		{
			SrcMac:    [6]uint8{0xaa, 0, 0, 0, 0, 1},
			DstMac:    [6]uint8{0xaa, 0, 0, 0, 0, 2},
			EthProto:  0x0800,
			Direction: bpf.DirectionEgress,
			DstZone:   bpf.ZoneExternal,
		}: {Bytes: 4242, Packets: 7, LastSeenNs: 1},
	}}

	cfg := config.Defaults()
	cfg.HTTP.Listen = "127.0.0.1:0"
	cfg.Scrape.Interval = 25 * time.Millisecond
	cfg.WAL.Path = walPath
	cfg.WAL.FlushInterval = 30 * time.Second // only the final flush writes
	cfg.WAL.Enabled = true

	log, err := logging.Init(cfg.Logging, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("logging.Init: %v", err)
	}
	ag, err := agent.New(agent.Options{Config: cfg, Reader: r, Log: log})
	if err != nil {
		t.Fatalf("agent.New: %v", err)
	}

	// Run with a context we never cancel — the only way out is the
	// server-error path triggered by closing the listener below.
	runErr := make(chan error, 1)
	go func() { runErr <- ag.Run(context.Background()) }()

	// Let the scraper absorb the seeded delta, then kill the server.
	time.Sleep(150 * time.Millisecond)
	if err := ag.CloseListenerForTest(); err != nil {
		t.Fatalf("close listener: %v", err)
	}

	select {
	case err := <-runErr:
		if err == nil {
			t.Error("Run returned nil; expected the server error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not exit within 2s of server failure")
	}

	res, err := wal.Load(walPath)
	if err != nil {
		t.Fatalf("wal.Load: %v", err)
	}
	if res.Source != wal.LoadFromPrimary || len(res.Records) == 0 {
		t.Fatalf("final flush did not run on server error: source=%v records=%d",
			res.Source, len(res.Records))
	}
	if res.Records[0].Counter.Total.Bytes != 4242 {
		t.Errorf("final flush Total.Bytes = %d, want 4242",
			res.Records[0].Counter.Total.Bytes)
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
