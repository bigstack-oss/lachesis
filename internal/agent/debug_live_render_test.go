//go:build manualrender

// Manual render harness — read-only Neutron fetch + local HTTP
// server that exposes the agent's /debug pages against live cluster
// data. NOT run by default CI; gated behind the `manualrender`
// build tag.
//
// Usage:
//
//	# With an admin-openrc file (preferred):
//	OS_CREDS_FILE=/path/to/admin-openrc.sh \
//	  GOWORK=off go test -tags manualrender -v -timeout 30m \
//	  -run TestRenderLivePages ./internal/agent/
//
//	# Or with individual OS_* env vars:
//	OS_AUTH_URL=https://keystone.example.com:5000/v3 \
//	OS_USERNAME=admin OS_PASSWORD=... OS_PROJECT_NAME=admin \
//	  GOWORK=off go test -tags manualrender -v -timeout 30m \
//	  -run TestRenderLivePages ./internal/agent/
//
// The harness prints two URLs to test output; open them in a browser
// to inspect the rendered topology and zone-map pages. The vendored
// cytoscape.min.js is served from the same local server so the
// topology graph renders without any network fetch.
//
// Ctrl-C ends the test cleanly. The harness does not write anything
// to the cluster — only read-only Neutron + Keystone list calls.
package agent

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"os/signal"
	"syscall"
	"testing"
	"time"

	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/metadata"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/neutron"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/web"
)

func TestRenderLivePages(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	creds, err := loadCredsFromEnv()
	if err != nil {
		t.Skipf("creds unavailable (set OS_CREDS_FILE or OS_AUTH_URL/OS_USERNAME/...): %v", err)
	}

	client, err := neutron.NewClient(ctx, creds)
	if err != nil {
		t.Fatalf("neutron auth (AuthURL=%s ProjectName=%s): %v",
			creds.AuthURL, creds.ProjectName, err)
	}
	t.Logf("authenticated against %s (project=%s)", creds.AuthURL, creds.ProjectName)

	snap, err := neutron.FetchSnapshot(ctx, client)
	if err != nil {
		t.Fatalf("fetch snapshot: %v", err)
	}
	t.Logf("snapshot: networks=%d subnets=%d ports=%d routers=%d",
		len(snap.Networks), len(snap.Subnets), len(snap.Ports), len(snap.Routers))

	entries, ambiguities, cycles := neutron.BuildTrie(snap.Networks, snap.Subnets, snap.Ports, snap.Routers)
	t.Logf("trie: entries=%d ambiguities=%d cycles=%d", len(entries), len(ambiguities), len(cycles))

	anomalies := neutron.DetectAnomalies(snap, entries, cycles, ambiguities)
	t.Logf("anomalies: cycles=%d ambiguities=%d dangling=%d zero-trie=%d dup-mac=%d (total=%d)",
		len(anomalies.Cycles), len(anomalies.Ambiguities), len(anomalies.DanglingRoutes),
		len(anomalies.ZeroTrieTenants), len(anomalies.DuplicateRouterMACs), anomalies.Total())

	a := &Agent{meta: metadata.New()}
	a.SetNeutronSnapshot(&snap)
	a.SetTrieEntries(entries)
	a.SetAnomalies(&anomalies)
	a.MarkNeutronSync(time.Now())

	mux := http.NewServeMux()
	mux.HandleFunc("/debug/topology", a.handleDebugTopology)
	mux.HandleFunc("/debug/topology/{tenant}", a.handleDebugTopologyTenant)
	mux.HandleFunc("/debug/zones", a.handleDebugZones)
	mux.HandleFunc("/debug/lookup", a.handleDebugLookup)
	mux.Handle("/debug/static/", http.StripPrefix("/debug/", http.FileServer(http.FS(web.Static))))

	srv := httptest.NewServer(mux)
	defer srv.Close()

	t.Logf("")
	t.Logf("  ┌─ Render harness ready ──────────────────────────────────")
	t.Logf("  │  Topology: %s/debug/topology", srv.URL)
	t.Logf("  │  Zones:    %s/debug/zones", srv.URL)
	t.Logf("  │  Lookup:   %s/debug/lookup?ip=<addr>[&tenant=<uuid>]", srv.URL)
	t.Logf("  │  Lookup:   %s/debug/lookup?mac=<addr>", srv.URL)
	t.Logf("  │")
	t.Logf("  │  Press Ctrl-C when done. (30-min context cap.)")
	t.Logf("  └─────────────────────────────────────────────────────────")
	t.Logf("")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	select {
	case <-sigCh:
		t.Logf("shutting down on signal")
	case <-ctx.Done():
		t.Logf("shutting down on timeout")
	}
}

// loadCredsFromEnv resolves Neutron credentials from the environment.
// If OS_CREDS_FILE points at an admin-openrc file we delegate to the
// existing ParseOpenRC; otherwise we fall back to reading individual
// OS_* variables. Either path yields the same [neutron.Credentials]
// the agent's cold-start consumes.
func loadCredsFromEnv() (neutron.Credentials, error) {
	if path := os.Getenv("OS_CREDS_FILE"); path != "" {
		return neutron.ParseOpenRC(path)
	}
	c := neutron.Credentials{
		AuthURL:       os.Getenv("OS_AUTH_URL"),
		Username:      os.Getenv("OS_USERNAME"),
		Password:      os.Getenv("OS_PASSWORD"),
		ProjectName:   os.Getenv("OS_PROJECT_NAME"),
		UserDomain:    envOrDefault("OS_USER_DOMAIN_NAME", "default"),
		ProjectDomain: envOrDefault("OS_PROJECT_DOMAIN_NAME", "default"),
		Region:        os.Getenv("OS_REGION_NAME"),
		Interface:     os.Getenv("OS_INTERFACE"),
	}
	if c.AuthURL == "" || c.Username == "" || c.Password == "" || c.ProjectName == "" {
		return neutron.Credentials{}, &missingCredErr{}
	}
	return c, nil
}

type missingCredErr struct{}

func (*missingCredErr) Error() string {
	return "set OS_CREDS_FILE=<openrc path> or OS_AUTH_URL/OS_USERNAME/OS_PASSWORD/OS_PROJECT_NAME"
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
