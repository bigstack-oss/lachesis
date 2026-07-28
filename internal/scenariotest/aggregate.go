package scenariotest

// Tuple keys the {tenant_id, zone, direction} label set; ExtTuple and
// ServerTuple refine it for expectations that pin the external_network
// label or a specific server.
type Tuple struct{ Tenant, Zone, Direction string }

type ExtTuple struct{ Tenant, Zone, Ext, Direction string }

type ServerTuple struct{ Server, Zone, Ext, Direction string }

// SumByTuple aggregates samples per label tuple. Summing (not
// last-wins) matters on multi-node clusters, where every agent
// exposes its own series for the same tenant.
func SumByTuple(samples []BytesSample) map[Tuple]float64 {
	m := make(map[Tuple]float64, len(samples))
	for _, s := range samples {
		m[Tuple{s.TenantID, s.Zone, s.Direction}] += s.Value
	}
	return m
}

// SumByExtTuple is [SumByTuple] refined by the external_network label.
func SumByExtTuple(samples []BytesSample) map[ExtTuple]float64 {
	m := make(map[ExtTuple]float64, len(samples))
	for _, s := range samples {
		m[ExtTuple{s.TenantID, s.Zone, s.ExternalNetwork, s.Direction}] += s.Value
	}
	return m
}

// SumByServerTuple aggregates the per-server family. A live-migrated
// server appears on several agents; summing per server is the
// consumption rule (docs/architecture/billing.md).
func SumByServerTuple(samples []ServerSample) map[ServerTuple]float64 {
	m := make(map[ServerTuple]float64, len(samples))
	for _, s := range samples {
		m[ServerTuple{s.ServerID, s.Zone, s.ExternalNetwork, s.Direction}] += s.Value
	}
	return m
}

// HasNodeInfo reports whether any sample carries node identity — a
// baseline captured before per-node stamping can't back a
// node-targeted expectation.
func HasNodeInfo(bytes []BytesSample, servers []ServerSample) bool {
	for _, s := range bytes {
		if s.Node != "" {
			return true
		}
	}
	for _, s := range servers {
		if s.Node != "" {
			return true
		}
	}
	return false
}

// SumBytesOnNode totals one node's tenant-family series for the
// tuple; ext "" matches any external_network (the same wildcard rule
// as the collective default path).
func SumBytesOnNode(samples []BytesSample, node, tenant, zone, ext, direction string) float64 {
	var total float64
	for _, s := range samples {
		if s.Node != node || s.TenantID != tenant || s.Zone != zone || s.Direction != direction {
			continue
		}
		if ext != "" && s.ExternalNetwork != ext {
			continue
		}
		total += s.Value
	}
	return total
}

// SumServersOnNode totals one node's per-server series; ext "" matches
// any external_network.
func SumServersOnNode(samples []ServerSample, node, server, zone, ext, direction string) float64 {
	var total float64
	for _, s := range samples {
		if s.Node != node || s.ServerID != server || s.Zone != zone || s.Direction != direction {
			continue
		}
		if ext != "" && s.ExternalNetwork != ext {
			continue
		}
		total += s.Value
	}
	return total
}

// SumServer totals a server's series for (zone, direction), across all
// external networks when ext is empty.
func SumServer(m map[ServerTuple]float64, server, zone, ext, direction string) float64 {
	if ext != "" {
		return m[ServerTuple{server, zone, ext, direction}]
	}
	var total float64
	for k, v := range m {
		if k.Server == server && k.Zone == zone && k.Direction == direction {
			total += v
		}
	}
	return total
}
