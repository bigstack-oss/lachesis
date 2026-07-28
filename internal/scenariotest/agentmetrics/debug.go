package agentmetrics

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/bigstack-oss/lachesis/internal/scenariotest"
)

// LookupMAC implements the MAC half of [scenariotest.MetricsSource]
// against the agent's /debug/lookup endpoint, derived from the metrics
// URL (the agent serves /metrics and /debug on one listener). A 200 with
// no mac_tenant_map section decodes as not-found — the endpoint reports
// what it saw, it does not 404 on misses.
func (c *Client) LookupMAC(ctx context.Context, metricsURL, mac string) (scenariotest.MACLookup, error) {
	u, err := debugURL(metricsURL, "lookup", mac)
	if err != nil {
		return scenariotest.MACLookup{}, err
	}
	var body struct {
		MAC *struct {
			Found    bool   `json:"found"`
			TenantID string `json:"tenant_id"`
			PortID   string `json:"port_id"`
		} `json:"mac_tenant_map"`
	}
	if err := c.getJSON(ctx, u, &body); err != nil {
		return scenariotest.MACLookup{}, err
	}
	if body.MAC == nil {
		return scenariotest.MACLookup{}, nil
	}
	return scenariotest.MACLookup{Found: body.MAC.Found, TenantID: body.MAC.TenantID, PortID: body.MAC.PortID}, nil
}

// LookupFlows implements the flow-query half of
// [scenariotest.MetricsSource] against /debug/flows, derived from the
// metrics URL like [Client.LookupMAC].
func (c *Client) LookupFlows(ctx context.Context, metricsURL, mac string) ([]scenariotest.FlowRow, error) {
	u, err := debugURL(metricsURL, "flows", mac)
	if err != nil {
		return nil, err
	}
	var body struct {
		Rows []scenariotest.FlowRow `json:"rows"`
	}
	if err := c.getJSON(ctx, u, &body); err != nil {
		return nil, err
	}
	return body.Rows, nil
}

// debugURL turns an agent's /metrics URL into one of its /debug/<query>
// endpoints. Both live on the same listener, so the metrics URL is the
// only endpoint the config carries; a URL that does not end in /metrics
// is a config error worth naming precisely.
func debugURL(metricsURL, query, mac string) (string, error) {
	base, ok := strings.CutSuffix(metricsURL, "/metrics")
	if !ok {
		return "", fmt.Errorf("%s: metrics URL %q does not end in /metrics — cannot derive /debug/%s (check cluster.agents[].metrics_url)", query, metricsURL, query)
	}
	return base + "/debug/" + query + "?mac=" + url.QueryEscape(mac), nil
}

// getJSON GETs u and decodes the body into out.
func (c *Client) getJSON(ctx context.Context, u string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return fmt.Errorf("debug: build request %s: %w", u, err)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("debug: get %s: %w", u, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("debug: get %s: status %d", u, resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("debug: decode %s: %w", u, err)
	}
	return nil
}
