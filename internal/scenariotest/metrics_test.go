package scenariotest

import (
	"context"
	"net/http"
	"net/http/httptest"
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
	for _, m := range []string{metricBytesTotal, metricAttachedInterfaces, metricAttachFailures} {
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
