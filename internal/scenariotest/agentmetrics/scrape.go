package agentmetrics

import (
	"context"

	"github.com/bigstack-oss/lachesis/internal/scenariotest"
)

// Scrape fetches and parses one agent's /metrics.
func (c *Client) Scrape(ctx context.Context, url string) (scenariotest.ScrapeResult, error) {
	fams, err := c.fetch(ctx, url)
	if err != nil {
		return scenariotest.ScrapeResult{}, err
	}
	r := scenariotest.ScrapeResult{Present: map[string]bool{}}
	for _, n := range []string{
		scenariotest.MetricBytesTotal, scenariotest.MetricAttachedInterfaces, scenariotest.MetricAttachFailures,
		scenariotest.MetricSettledFlows, scenariotest.MetricLingeringGhosts, scenariotest.MetricServerBytesTotal,
		scenariotest.MetricNeutronAnomalies, scenariotest.MetricTenantSettledTuples,
		scenariotest.MetricUnresolvedResolved, scenariotest.MetricGCEvictions,
		scenariotest.MetricCountersReset,
	} {
		_, ok := fams[n]
		r.Present[n] = ok
	}
	r.AttachedInterfaces = familySum(fams, scenariotest.MetricAttachedInterfaces)
	r.AttachFailures = familySum(fams, scenariotest.MetricAttachFailures)
	r.SettledFlows = familySum(fams, scenariotest.MetricSettledFlows)
	r.SettledTuples = familySum(fams, scenariotest.MetricTenantSettledTuples) +
		familySum(fams, scenariotest.MetricServerSettledTuples) +
		familySum(fams, scenariotest.MetricTotalSettledTuples)
	r.UnresolvedResolved = familySum(fams, scenariotest.MetricUnresolvedResolved)
	r.PressureReliefEvictions = reasonSum(fams, scenariotest.MetricGCEvictions, scenariotest.ReasonPressureRelief)
	r.LingeringGhosts = familySum(fams, scenariotest.MetricLingeringGhosts)
	r.Bytes = bytesSamples(fams)
	r.Servers = serverSamples(fams)
	r.PortBytes = portSamples(fams)
	r.Anomalies = anomalySamples(fams)
	r.CountersResetEpoch = familySum(fams, scenariotest.MetricCountersReset)
	return r, nil
}
