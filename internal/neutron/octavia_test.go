package neutron

import (
	"testing"
)

// ampSnap builds the shared topology for the AmphoraOwnerByPort tests:
// one amphora-provider load balancer owned by tenant T1, its Amphora
// running as Nova instance "nova-amp1" with three ports (management,
// VIP-network vrrp, plugged member network), the LB's VIP reservation
// port, and one unrelated tenant VM.
//
// The port shapes mirror what a live OVN-Yoga deployment produces: the
// Amphora's data ports are ordinary `compute:nova` ports owned by the
// Octavia service project, carrying no marker of their own — only the
// shared `device_id` ties them to the Amphora.
func ampSnap() Snapshot {
	return Snapshot{
		Ports: []Port{
			// Management port: holds LBNetworkIP, carries health-manager
			// heartbeats. Must NOT be re-attributed.
			{ID: "port-amp-mgmt", DeviceOwner: "compute:nova", DeviceID: "nova-amp1",
				ProjectID: "service", MACAddress: "fa:16:3e:00:00:01",
				FixedIPs: []FixedIP{{SubnetID: "sub-mgmt", IPAddress: "10.254.3.218"}}},
			// vrrp / VIP-network data port.
			{ID: "port-amp-vrrp", DeviceOwner: "compute:nova", DeviceID: "nova-amp1",
				ProjectID: "service", MACAddress: "fa:16:3e:00:00:02",
				FixedIPs: []FixedIP{{SubnetID: "sub-vip", IPAddress: "192.168.1.99"}}},
			// Member-network port Octavia plugged for an off-subnet pool
			// member. Nova minted it, so it is indistinguishable from any
			// other compute port except by device_id.
			{ID: "port-amp-member", DeviceOwner: "compute:nova", DeviceID: "nova-amp1",
				ProjectID: "service", MACAddress: "fa:16:3e:00:00:03",
				FixedIPs: []FixedIP{{SubnetID: "sub-member", IPAddress: "10.131.2.7"}}},
			// The LB's VIP reservation port: already owned by T1, never on
			// the wire, and not bound to the Nova instance.
			{ID: "port-vip", DeviceOwner: "Octavia", DeviceID: "lb-lb1",
				ProjectID: "T1", MACAddress: "fa:16:3e:00:00:04",
				FixedIPs: []FixedIP{{SubnetID: "sub-vip", IPAddress: "192.168.1.47"}}},
			// Unrelated tenant VM.
			{ID: "port-vm", DeviceOwner: "compute:nova", DeviceID: "nova-vm1",
				ProjectID: "T2", MACAddress: "fa:16:3e:00:00:05",
				FixedIPs: []FixedIP{{SubnetID: "sub-vip", IPAddress: "192.168.1.20"}}},
		},
		LoadBalancers: []LoadBalancer{
			{ID: "lb1", ProjectID: "T1", Provider: "amphora"},
		},
		Amphorae: []Amphora{
			{ID: "amp1", LoadBalancerID: "lb1", ComputeID: "nova-amp1",
				LBNetworkIP: "10.254.3.218", Status: "ALLOCATED"},
		},
	}
}

func TestAmphoraOwnerByPort(t *testing.T) {
	snap := ampSnap()
	got := AmphoraOwnerByPort(&snap)

	// The two data ports re-attribute; nothing else does.
	want := map[string]string{
		"port-amp-vrrp":   "T1",
		"port-amp-member": "T1",
	}
	for port, owner := range want {
		if got[port] != owner {
			t.Errorf("port %s = %q, want %q", port, got[port], owner)
		}
	}
	for _, port := range []string{"port-amp-mgmt", "port-vip", "port-vm"} {
		if owner, ok := got[port]; ok {
			t.Errorf("port %s re-attributed to %q, want absent", port, owner)
		}
	}
	if len(got) != len(want) {
		t.Errorf("map has %d entries, want %d: %v", len(got), len(want), got)
	}
}

// TestAmphoraOwnerByPort_MemberPortNeedsComputeIDJoin pins the reason
// the join keys on device_id rather than the Amphora's vrrp_port_id: a
// plugged member-network port is created by Nova on interface-attach
// and carries no Octavia marker, so any join narrower than the Nova
// instance UUID silently leaves Segment 2 billing the service project.
func TestAmphoraOwnerByPort_MemberPortNeedsComputeIDJoin(t *testing.T) {
	snap := ampSnap()
	got := AmphoraOwnerByPort(&snap)
	if got["port-amp-member"] != "T1" {
		t.Fatalf("plugged member-network port = %q, want T1", got["port-amp-member"])
	}
}

func TestAmphoraOwnerByPort_Exclusions(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Snapshot)
		wantLen int
	}{
		{
			name:    "non-amphora provider is left alone",
			mutate:  func(s *Snapshot) { s.LoadBalancers[0].Provider = "ovn" },
			wantLen: 0,
		},
		{
			name:    "deprecated octavia provider alias is accepted",
			mutate:  func(s *Snapshot) { s.LoadBalancers[0].Provider = "octavia" },
			wantLen: 2,
		},
		{
			name:    "empty provider is treated as the amphora default",
			mutate:  func(s *Snapshot) { s.LoadBalancers[0].Provider = "" },
			wantLen: 2,
		},
		{
			name:    "deleted amphora claims nothing",
			mutate:  func(s *Snapshot) { s.Amphorae[0].Status = amphoraStatusDeleted },
			wantLen: 0,
		},
		{
			name:    "amphora with no compute binding is skipped",
			mutate:  func(s *Snapshot) { s.Amphorae[0].ComputeID = "" },
			wantLen: 0,
		},
		{
			name:    "amphora whose load balancer is missing is skipped",
			mutate:  func(s *Snapshot) { s.Amphorae[0].LoadBalancerID = "lb-gone" },
			wantLen: 0,
		},
		{
			name:    "load balancer with no owning project is skipped",
			mutate:  func(s *Snapshot) { s.LoadBalancers[0].ProjectID = "" },
			wantLen: 0,
		},
		{
			name:    "octavia lists absent leaves every port alone",
			mutate:  func(s *Snapshot) { s.LoadBalancers, s.Amphorae = nil, nil },
			wantLen: 0,
		},
		{
			name: "unknown management address stops excluding the mgmt port",
			// LBNetworkIP is the only handle on which port is management;
			// without it the conservative outcome is to re-attribute all
			// three rather than none, so the billing path still works.
			mutate:  func(s *Snapshot) { s.Amphorae[0].LBNetworkIP = "" },
			wantLen: 3,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			snap := ampSnap()
			tt.mutate(&snap)
			got := AmphoraOwnerByPort(&snap)
			if len(got) != tt.wantLen {
				t.Errorf("AmphoraOwnerByPort() = %v (%d entries), want %d", got, len(got), tt.wantLen)
			}
		})
	}
}

// TestAmphoraOwnerByPort_ActiveStandby covers the two-Amphora topology:
// both VMs serve one load balancer, so every data port of both bills
// the same tenant.
func TestAmphoraOwnerByPort_ActiveStandby(t *testing.T) {
	snap := ampSnap()
	snap.Amphorae = append(snap.Amphorae, Amphora{
		ID: "amp2", LoadBalancerID: "lb1", ComputeID: "nova-amp2",
		LBNetworkIP: "10.254.3.219", Status: "ALLOCATED",
	})
	snap.Ports = append(snap.Ports,
		Port{ID: "port-amp2-mgmt", DeviceOwner: "compute:nova", DeviceID: "nova-amp2",
			ProjectID: "service", MACAddress: "fa:16:3e:00:00:06",
			FixedIPs: []FixedIP{{SubnetID: "sub-mgmt", IPAddress: "10.254.3.219"}}},
		Port{ID: "port-amp2-vrrp", DeviceOwner: "compute:nova", DeviceID: "nova-amp2",
			ProjectID: "service", MACAddress: "fa:16:3e:00:00:07",
			FixedIPs: []FixedIP{{SubnetID: "sub-vip", IPAddress: "192.168.1.100"}}},
	)

	got := AmphoraOwnerByPort(&snap)
	if got["port-amp2-vrrp"] != "T1" {
		t.Errorf("standby vrrp port = %q, want T1", got["port-amp2-vrrp"])
	}
	if _, ok := got["port-amp2-mgmt"]; ok {
		t.Error("standby management port re-attributed, want absent")
	}
}

// TestAmphoraOwnerByPort_MultipleLoadBalancers checks the owner is
// resolved per Amphora, not globally: two tenants' load balancers on
// one deployment must not cross-attribute.
func TestAmphoraOwnerByPort_MultipleLoadBalancers(t *testing.T) {
	snap := ampSnap()
	snap.LoadBalancers = append(snap.LoadBalancers,
		LoadBalancer{ID: "lb2", ProjectID: "T9", Provider: "amphora"})
	snap.Amphorae = append(snap.Amphorae, Amphora{
		ID: "amp9", LoadBalancerID: "lb2", ComputeID: "nova-amp9",
		LBNetworkIP: "10.254.3.240", Status: "ALLOCATED",
	})
	snap.Ports = append(snap.Ports,
		Port{ID: "port-amp9-vrrp", DeviceOwner: "compute:nova", DeviceID: "nova-amp9",
			ProjectID: "service", MACAddress: "fa:16:3e:00:00:09",
			FixedIPs: []FixedIP{{SubnetID: "sub-vip", IPAddress: "192.168.1.101"}}},
	)

	got := AmphoraOwnerByPort(&snap)
	if got["port-amp-vrrp"] != "T1" {
		t.Errorf("lb1 vrrp port = %q, want T1", got["port-amp-vrrp"])
	}
	if got["port-amp9-vrrp"] != "T9" {
		t.Errorf("lb2 vrrp port = %q, want T9", got["port-amp9-vrrp"])
	}
}
