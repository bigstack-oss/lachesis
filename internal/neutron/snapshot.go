package neutron

import (
	"context"
	"fmt"
)

// Snapshot is the four Neutron resource lists the agent consumes
// together at cold-start (and again on each Sprint 7 Kafka
// full-resync). Bundled into one type so callers can pass it
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
	return s, nil
}
