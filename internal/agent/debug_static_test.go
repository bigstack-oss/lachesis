package agent

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/web"
)

// TestDebugStatic_ServesCytoscape pins the URL → embed.FS plumbing
// for the vendored Cytoscape.js. A regression in either the
// /debug/static/ route registration or the StripPrefix path would
// make the topology page silently fail (page renders blank, no
// browser console error visible to the agent operator).
func TestDebugStatic_ServesCytoscape(t *testing.T) {
	// Build the static handler exactly as buildHTTPHandler wires it.
	// Re-stating it here is intentional: this test asserts the
	// agent-side contract, not the embed package itself.
	h := http.StripPrefix("/debug/", http.FileServer(http.FS(web.Static)))

	req := httptest.NewRequest(http.MethodGet, "/debug/static/cytoscape.min.js", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	// Cytoscape 3.x minified is ~370KB. Any major shrink suggests a
	// stale or corrupted vendored file.
	if got := rec.Body.Len(); got < 100_000 {
		t.Errorf("body = %d bytes, want ≥100k", got)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "javascript") {
		t.Errorf("Content-Type = %q, want to contain 'javascript'", ct)
	}
	// Vendor banner sanity: the first chars should be the MIT license
	// header. If this fails, someone replaced the .min.js with the
	// unminified source (which starts differently) or a different lib.
	if got := rec.Body.String(); !strings.HasPrefix(got, "/**") {
		t.Errorf("body prefix = %q, want '/**' (Cytoscape MIT banner)", got[:min(20, len(got))])
	}
}
