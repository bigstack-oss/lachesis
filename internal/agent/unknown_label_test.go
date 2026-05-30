package agent_test

import (
	"testing"

	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/bpf"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/metadata"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/metrics"
)

// TestUnknownTenantLabelMatchesStub locks the contract that an empty
// metadata resolver and the metrics.UnknownTenant stub emit the same
// tenant_id label. The two producers live in different packages
// (metadata is L2, metrics is L4) and metadata must not import metrics,
// so nothing at compile time forces the literals to agree — yet they
// must, because Prometheus rate() spans the cold-start transition from
// the stub's "unknown" to resolved project UUIDs. agent.New's
// resolverOrDefault relies on this equivalence; this test enforces it.
func TestUnknownTenantLabelMatchesStub(t *testing.T) {
	var key bpf.FlowKey // zero key: guaranteed mac_tenant_map miss

	got := metadata.NewResolver(metadata.New()).ResolveTenant(key)
	want := metrics.UnknownTenant{}.ResolveTenant(key)
	if got != want {
		t.Fatalf("unknown tenant label mismatch: metadata resolver = %q, metrics stub = %q", got, want)
	}
}
