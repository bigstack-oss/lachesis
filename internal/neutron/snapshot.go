package neutron

import (
	"context"
	"fmt"
)

// Snapshot is the four Neutron resource lists the agent consumes
// together at cold-start and at every full-resync triggered by the
// Kafka updater. Bundled into one type so callers can pass it
// around as a single value instead of four parallel slices.
//
// The fields are slices in API-iteration order — no sorting
// guarantee. Downstream consumers that need stable ordering
// (e.g. the trie builder) sort their own derived outputs.
type Snapshot struct {
	Networks []Network
	Subnets  []Subnet
	Ports    []Port
	Routers  []Router
	// Projects is the Keystone project list. Carried alongside the
	// Neutron resources because Neutron returns project_id as a bare
	// UUID; consumers that need a human-readable label (e.g. /debug
	// HTML pages, log enrichment) resolve through this slice.
	Projects []Project
}

// ProjectName returns the Keystone project's name for id, or id
// itself if no matching project is present. Linear scan — projects
// are O(tens), so the constant factor beats a precomputed map.
func (s Snapshot) ProjectName(id string) string {
	for _, p := range s.Projects {
		if p.ID == id {
			return p.Name
		}
	}
	return id
}

// FetchSnapshot issues the four list calls in sequence and returns
// the populated [Snapshot]. The calls share the same client (so
// the same Keystone token) and run sequentially — gophercloud
// already paginates each call internally via `AllPages`.
//
// Errors are wrapped with the resource name so a partial-failure
// log identifies which call failed. The function returns on first
// error; downstream code is expected to retry the whole snapshot
// rather than mix old and new resource lists.
func FetchSnapshot(ctx context.Context, c *Client) (Snapshot, error) {
	var s Snapshot
	var err error
	if s.Networks, err = c.ListNetworks(ctx); err != nil {
		return s, fmt.Errorf("list networks: %w", err)
	}
	if s.Subnets, err = c.ListSubnets(ctx); err != nil {
		return s, fmt.Errorf("list subnets: %w", err)
	}
	if s.Ports, err = c.ListPorts(ctx); err != nil {
		return s, fmt.Errorf("list ports: %w", err)
	}
	if s.Routers, err = c.ListRouters(ctx); err != nil {
		return s, fmt.Errorf("list routers: %w", err)
	}
	if s.Projects, err = c.ListProjects(ctx); err != nil {
		return s, fmt.Errorf("list projects: %w", err)
	}
	return s, nil
}
