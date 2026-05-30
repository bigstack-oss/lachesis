package neutron

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
}
