// trace.go defines the wire-level logging tier below DEBUG: one line
// per OpenStack API call, agent /metrics scrape, or VM SSH exec —
// enough to see what was sent and what came back without reading code.
package scenariotest

import (
	"log/slog"
	"net/http"
	"time"
)

// LevelTrace is the wire tier below [slog.LevelDebug]. Request and
// response bodies are deliberately never logged at any level: Keystone
// auth requests carry the admin password and every response carries
// tokens — method/URL/status/duration answers "what happened on the
// wire" without turning the log into a credential leak.
const LevelTrace = slog.Level(-8)

// NewTraceTransport wraps base (nil means [http.DefaultTransport]) so
// every request emits one [LevelTrace] line. With trace disabled on
// the logger the overhead is one Enabled check per request.
func NewTraceTransport(base http.RoundTripper, log *slog.Logger) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return traceTransport{base: base, log: log}
}

type traceTransport struct {
	base http.RoundTripper
	log  *slog.Logger
}

func (t traceTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	start := time.Now()
	resp, err := t.base.RoundTrip(req)
	dur := time.Since(start).Round(time.Millisecond)
	if err != nil {
		t.log.Log(req.Context(), LevelTrace, "http",
			"method", req.Method, "url", req.URL.Redacted(), "err", err, "dur", dur)
		return resp, err
	}
	t.log.Log(req.Context(), LevelTrace, "http",
		"method", req.Method, "url", req.URL.Redacted(), "status", resp.StatusCode, "dur", dur)
	return resp, nil
}
