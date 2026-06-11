// options.go defines [Options], the inputs to [New], together with the
// small helpers that validate and default them. Keeping it apart from
// agent.go leaves that file solely about the [Agent] type and its
// lifecycle.

package agent

import (
	"errors"

	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/config"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/logging"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/metadata"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/metrics"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/scraper"
)

// Options bundles the inputs to [New]. ConfigPath is the YAML file
// the [runtime.Manager] will re-read on SIGHUP; empty disables
// SIGHUP reload while keeping /debug functional.
type Options struct {
	Config     config.Config
	ConfigPath string
	Reader     scraper.MapReader
	Log        *logging.Handle
	// Resolver maps FlowKey → tenant_id label. nil means a
	// [metadata.NewResolver] wrapping the Agent's own
	// [metadata.ShardedMetadataMap], which starts empty and is
	// populated by Bootstrap (Linux) from Neutron. Tests can
	// inject a mock resolver to pin label outputs without
	// pre-populating the metadata map.
	Resolver metrics.TenantResolver
}

// validate rejects required fields that the caller forgot to fill.
// Returned errors are intended for [New]; no validation is done on
// optional fields here (defaults are applied elsewhere).
func (o Options) validate() error {
	if o.Reader == nil {
		return errors.New("agent: Options.Reader is nil")
	}
	if o.Log == nil {
		return errors.New("agent: Options.Log is nil")
	}
	return nil
}

// resolverOrDefault returns the caller's [TenantResolver] when set,
// otherwise a [metadata.NewResolver] wrapping meta. Centralising
// the default keeps [New] free of branches that aren't about
// wiring. An empty meta yields the same "tenant_id=unknown" labels
// the old [metrics.UnknownTenant] stub produced, so pre-Bootstrap
// scrapes (and the no-Neutron loadtest harness) behave
// indistinguishably from before this change.
func (o Options) resolverOrDefault(meta *metadata.ShardedMetadataMap) metrics.TenantResolver {
	if o.Resolver != nil {
		return o.Resolver
	}
	return metadata.NewResolver(meta)
}
