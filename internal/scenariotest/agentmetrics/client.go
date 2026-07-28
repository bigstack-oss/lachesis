// Package agentmetrics is the live [scenariotest.MetricsSource]: it
// reads a running agent's observability surfaces over HTTP — the
// Prometheus text exposition at /metrics and the JSON /debug queries on
// the same listener — and parses them into the harness's sample types.
//
// It is one of scenariotest's leaf driver packages: it depends on the
// core harness for the wire contract (the metric-name constants and the
// sample structs) and on nothing else in the tree. The core never
// imports it — subpackages use the harness, not the other way around.
package agentmetrics

import (
	"context"
	"fmt"
	"net/http"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"
)

// Client is the HTTP-backed [scenariotest.MetricsSource].
type Client struct {
	HTTP *http.Client
}

// New returns a [Client] using c, or http.DefaultClient when c is nil.
func New(c *http.Client) *Client {
	if c == nil {
		c = http.DefaultClient
	}
	return &Client{HTTP: c}
}

func (c *Client) fetch(ctx context.Context, url string) (map[string]*dto.MetricFamily, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("metrics: build request %s: %w", url, err)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("metrics: scrape %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("metrics: scrape %s: status %d", url, resp.StatusCode)
	}
	// NewTextParser is required: a zero-value TextParser carries an
	// unset name-validation scheme and panics. UTF8 is the library's
	// current default and accepts the agent's metric names.
	parser := expfmt.NewTextParser(model.UTF8Validation)
	fams, err := parser.TextToMetricFamilies(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("metrics: parse %s: %w", url, err)
	}
	return fams, nil
}
