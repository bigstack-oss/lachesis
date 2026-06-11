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
//	  -run TestRenderLivePages ./internal/debug/
//
//	# Or with individual OS_* env vars:
//	OS_AUTH_URL=https://keystone.example.com:5000/v3 \
//	OS_USERNAME=admin OS_PASSWORD=... OS_PROJECT_NAME=admin \
//	  GOWORK=off go test -tags manualrender -v -timeout 30m \
//	  -run TestRenderLivePages ./internal/debug/
//
// The harness prints the page URLs to test output; open them in a
// browser to inspect the rendered pages. Append ?format=json to any
// page for the machine view.
//
// Ctrl-C ends the test cleanly. The harness does not write anything
// to the cluster — only read-only Neutron + Keystone list calls.
package debug

import (
	"context"
	"net/http/httptest"
	"os"
	"os/signal"
	"syscall"
	"testing"
	"time"

	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/neutron"
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

	var snap neutron.Snapshot
	if snap.Networks, err = client.ListNetworks(ctx); err != nil {
		t.Fatalf("list networks: %v", err)
	}
	if snap.Subnets, err = client.ListSubnets(ctx); err != nil {
		t.Fatalf("list subnets: %v", err)
	}
	if snap.Ports, err = client.ListPorts(ctx); err != nil {
		t.Fatalf("list ports: %v", err)
	}
	if snap.Routers, err = client.ListRouters(ctx); err != nil {
		t.Fatalf("list routers: %v", err)
	}
	if snap.Projects, err = client.ListProjects(ctx); err != nil {
		t.Fatalf("list projects: %v", err)
	}
	t.Logf("snapshot: networks=%d subnets=%d ports=%d routers=%d projects=%d",
		len(snap.Networks), len(snap.Subnets), len(snap.Ports), len(snap.Routers), len(snap.Projects))

	entries, ambiguities, cycles := neutron.BuildTrie(snap)
	t.Logf("trie: entries=%d ambiguities=%d cycles=%d", len(entries), len(ambiguities), len(cycles))

	anomalies := neutron.DetectAnomalies(snap, entries, cycles, ambiguities)
	t.Logf("anomalies: cycles=%d ambiguities=%d dangling=%d zero-trie=%d dup-mac=%d (total=%d)",
		len(anomalies.Cycles), len(anomalies.Ambiguities), len(anomalies.DanglingRoutes),
		len(anomalies.ZeroTrieTenants), len(anomalies.DuplicateRouterMACs), anomalies.Total())

	now := time.Now()
	s := New(Options{
		Snapshot:  func() *neutron.Snapshot { return &snap },
		Trie:      func() []neutron.TrieEntry { return entries },
		Anomalies: func() *neutron.Anomalies { return &anomalies },
		LastSync:  func() time.Time { return now },
	})

	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	t.Logf("")
	t.Logf("  ┌─ Render harness ready ──────────────────────────────────")
	t.Logf("  │  Index:     %s/debug", srv.URL)
	t.Logf("  │  Anomalies: %s/debug/anomalies", srv.URL)
	t.Logf("  │  Zones:     %s/debug/zones", srv.URL)
	t.Logf("  │  Topology:  %s/debug/topology", srv.URL)
	t.Logf("  │  Lookup:    %s/debug/lookup?ip=<addr>[&tenant=<uuid>]", srv.URL)
	t.Logf("  │  Lookup:    %s/debug/lookup?mac=<addr>", srv.URL)
	t.Logf("  │")
	t.Logf("  │  Append ?format=json to any page for the machine view.")
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
