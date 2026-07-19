# ADR 0013 — Pull-based /metrics over pushing usage records

**Status:** accepted

## Context

The billing pipeline needs the counters the agent produces. The push-shaped alternatives feel natural for billing — produce usage records to Kafka, POST them to a billing API, or push samples through a Prometheus Pushgateway — and are how CDR-style metering agents work. The agent already speaks Kafka (as a consumer, for metadata events), so a producer would be cheap to bolt on.

## Decision

The agent exposes **pull only**: lifetime-cumulative counters on `/metrics` (the custom Collector, [ADR 0007](./0007-custom-collector-over-countervec.md)), consumed by endpoint-sample subtraction ([billing.md](../architecture/billing.md)). No producer, no push path, no delivery machinery.

1. **Cumulative + pull makes loss self-healing.** Every sample carries the lifetime total, so a missed scrape costs *resolution*, never *bytes* — the next sample includes everything since. Pushing deltas inverts that: every lost message is permanent under-billing, so the transport must guarantee delivery. Pushing cumulatives is just scraping with the initiative reversed, minus the retry-for-free semantics.
2. **Consumer downtime costs zero agent code.** TSDB retention (90 days on the target platform) makes any missed billing period backfillable; the agent needs no outbound buffering, backpressure, acknowledgement tracking, or per-consumer cursors. The WAL covers agent restarts; retention covers consumer outages — neither needs the other's machinery.
3. **Keeps the broker out of the billing path.** Kafka is an *input* dependency (metadata events) with a 5-minute reconcile safety net when it's down ([boot-and-recovery.md](../architecture/boot-and-recovery.md)). Producing usage records would make broker availability a billing-*output* dependency, and a broker outage would demand exactly the unbounded buffering this design refuses to build. The agent is consumer-only by construction.
4. **One surface for billing and operations.** The same endpoint serves the health catalog and the billing families; the platform Prometheus already scrapes it. A push path would be a second export surface with its own auth, schema-evolution, and monitoring story.
5. **Prometheus's own guidance agrees** — the Pushgateway is explicitly not intended for service-level metrics.

## Consequences

- The agent's promise ends at `/metrics`: cumulative, monotone, restart-surviving series (Contract 7). Rating, ETL cadence, and durable billing rows are the platform's ([billing.md](../architecture/billing.md)).
- Prometheus durability, retention, and HA become load-bearing platform responsibilities — a stated non-goal for the agent.
- Sub-scrape-interval granularity and per-event records are out of scope; if ever needed, they are a billing-pipeline distillation of the scraped series, not an agent push path.

**When push is the right answer:** event-billed products (per-request CDRs), strict per-record delivery-audit requirements, or sinks that cannot scrape. None apply to byte metering with monotone counters.
