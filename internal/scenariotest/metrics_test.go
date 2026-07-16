package scenariotest

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const sampleExposition = `# HELP lachesis_bytes_total Network bytes observed by the agent.
# TYPE lachesis_bytes_total counter
lachesis_bytes_total{tenant_id="u-T1",zone="same_tenant",direction="tx"} 1.048576e+06
lachesis_bytes_total{tenant_id="u-T1",zone="same_tenant",direction="rx"} 524288
# HELP lachesis_attached_interfaces Number of interfaces currently carrying telemetry TC programs.
# TYPE lachesis_attached_interfaces gauge
lachesis_attached_interfaces 3
# HELP lachesis_tc_attach_failures_total TC clsact attach failures.
# TYPE lachesis_tc_attach_failures_total counter
lachesis_tc_attach_failures_total{iface_kind="tap"} 0
# HELP lachesis_server_bytes_total Per-server network bytes.
# TYPE lachesis_server_bytes_total counter
lachesis_server_bytes_total{server_id="srv-1",tenant_id="u-T1",zone="external",external_network="pub",direction="tx"} 4096
# HELP lachesis_neutron_anomalies Count of topology anomalies by class.
# TYPE lachesis_neutron_anomalies gauge
lachesis_neutron_anomalies{class="cycle"} 4
lachesis_neutron_anomalies{class="multi_external_path"} 2
`

func TestHTTPMetrics_Scrape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(sampleExposition))
	}))
	defer srv.Close()

	res, err := NewHTTPMetrics(nil).Scrape(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("Scrape: %v", err)
	}
	for _, m := range []string{metricBytesTotal, metricAttachedInterfaces, metricAttachFailures,
		metricServerBytesTotal, metricNeutronAnomalies} {
		if !res.Present[m] {
			t.Errorf("metric %s reported absent", m)
		}
	}
	if res.AttachedInterfaces != 3 {
		t.Errorf("AttachedInterfaces = %v, want 3", res.AttachedInterfaces)
	}
	if res.AttachFailures != 0 {
		t.Errorf("AttachFailures = %v, want 0", res.AttachFailures)
	}

	tx := findBytes(res.Bytes, "u-T1", "same_tenant", "tx")
	if tx == nil || tx.Value != 1048576 {
		t.Errorf("tx sample = %+v, want value 1048576", tx)
	}
	rx := findBytes(res.Bytes, "u-T1", "same_tenant", "rx")
	if rx == nil || rx.Value != 524288 {
		t.Errorf("rx sample = %+v, want value 524288", rx)
	}

	// The per-server family parses with all five labels...
	if len(res.Servers) != 1 {
		t.Fatalf("Servers = %+v, want 1 sample", res.Servers)
	}
	want := ServerSample{ServerID: "srv-1", TenantID: "u-T1", Zone: "external",
		ExternalNetwork: "pub", Direction: "tx", Value: 4096}
	if res.Servers[0] != want {
		t.Errorf("server sample = %+v, want %+v", res.Servers[0], want)
	}
	// ...and the anomalies gauge breaks out by class.
	if res.Anomalies["cycle"] != 4 || res.Anomalies["multi_external_path"] != 2 {
		t.Errorf("anomalies = %v, want cycle:4 multi_external_path:2", res.Anomalies)
	}
}

func TestHTTPMetrics_MissingMetric(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("# TYPE other_metric gauge\nother_metric 1\n"))
	}))
	defer srv.Close()

	res, err := NewHTTPMetrics(nil).Scrape(context.Background(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if res.Present[metricBytesTotal] || res.Present[metricAttachedInterfaces] {
		t.Errorf("required metrics should be absent: %+v", res.Present)
	}
}

func TestHTTPMetrics_ScrapeError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	if _, err := NewHTTPMetrics(nil).Scrape(context.Background(), srv.URL); err == nil {
		t.Fatal("want error on 500, got nil")
	}
}

func findBytes(samples []BytesSample, tenant, zone, dir string) *BytesSample {
	for i := range samples {
		s := &samples[i]
		if s.TenantID == tenant && s.Zone == zone && s.Direction == dir {
			return s
		}
	}
	return nil
}

// TestHTTPMetrics_LookupMAC: the live MetricsSource derives the
// /debug/lookup URL from the metrics URL and parses the
// mac_tenant_map section; a body without the section is a clean
// not-found, not an error.
func TestHTTPMetrics_LookupMAC(t *testing.T) {
	var gotPath, gotMAC string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotMAC = r.URL.Query().Get("mac")
		if gotMAC == "fa:16:3e:00:00:01" {
			fmt.Fprint(w, `{"query":{"mac":"fa:16:3e:00:00:01"},"mac_tenant_map":{"found":true,"tenant_id":"proj-a"}}`)
			return
		}
		fmt.Fprint(w, `{"query":{"mac":"x"}}`)
	}))
	defer srv.Close()
	h := NewHTTPMetrics(srv.Client())

	lk, err := h.LookupMAC(context.Background(), srv.URL+"/metrics", "fa:16:3e:00:00:01")
	if err != nil {
		t.Fatalf("LookupMAC: %v", err)
	}
	if gotPath != "/debug/lookup" {
		t.Errorf("lookup path = %q, want /debug/lookup (derived from metrics URL)", gotPath)
	}
	if !lk.Found || lk.TenantID != "proj-a" {
		t.Errorf("lookup = %+v, want found proj-a", lk)
	}

	lk, err = h.LookupMAC(context.Background(), srv.URL+"/metrics", "fa:16:3e:00:00:99")
	if err != nil {
		t.Fatalf("LookupMAC (miss): %v", err)
	}
	if lk.Found {
		t.Errorf("missing mac_tenant_map section must decode as not-found: %+v", lk)
	}
}

// TestHTTPMetrics_LookupMACRejectsUnexpectedURL: a metrics URL that
// doesn't end in /metrics can't derive the debug endpoint — fail with
// a config-pointing error instead of GETting a guessed URL.
func TestHTTPMetrics_LookupMACRejectsUnexpectedURL(t *testing.T) {
	h := NewHTTPMetrics(nil)
	_, err := h.LookupMAC(context.Background(), "http://cc1:9090/metrics/", "fa:16:3e:00:00:01")
	if err == nil || !strings.Contains(err.Error(), "metrics_url") {
		t.Fatalf("want config-pointing derivation error, got %v", err)
	}
}
