package neutron

import "testing"

func TestIsVMPort(t *testing.T) {
	tests := []struct {
		deviceOwner string
		want        bool
	}{
		{"compute:nova", true},
		{"compute:Octavia", true}, // older Octavia
		{"Octavia", true},
		{"Octavia:health-mgr", true},
		{"manila:share", true},
		{"baremetal:nova", true},
		{"cube:mgr", true}, // CubeCOS internal management VMs
		{"trunk:subport", true},
		// network:* never VM (the partition rule).
		{"network:router_interface", false},
		{"network:dhcp", false},
		{"network:floatingip", false}, // bookkeeping — neither infra nor VM
		{"network:remote_managed", false},
		// Unbound.
		{"", false},
	}
	for _, tc := range tests {
		if got := IsVMPort(tc.deviceOwner); got != tc.want {
			t.Errorf("IsVMPort(%q) = %v, want %v", tc.deviceOwner, got, tc.want)
		}
	}
}

func TestIsKnownVMOwner(t *testing.T) {
	tests := []struct {
		deviceOwner string
		want        bool
	}{
		// Verified known-VM owners.
		{"compute:nova", true},
		{"compute:Octavia", true},
		{"compute:availability-zone-2", true},
		{"Octavia", true},
		{"Octavia:health-mgr", true},
		{"manila:share", true},
		{"baremetal:nova", true},
		{"trunk:subport", true},
		{"cube:mgr", true},

		// Same-prefix but not on the catalogue (`cube:mgr` is exact match).
		{"cube:something-else", false},

		// IsVMPort would admit these but they're vendor / future / unknown.
		{"vendor:weird-thing", false},
		{"oslo:something", false},

		// Already excluded by IsVMPort (network:* + empty).
		{"network:router_interface", false},
		{"network:floatingip", false},
		{"", false},
	}
	for _, tc := range tests {
		if got := IsKnownVMOwner(tc.deviceOwner); got != tc.want {
			t.Errorf("IsKnownVMOwner(%q) = %v, want %v", tc.deviceOwner, got, tc.want)
		}
	}
}

// TestIsKnownVMOwnerImpliesIsVMPort verifies the predicate
// hierarchy: every known VM-owner must also pass the broader
// IsVMPort. The reverse is not required — IsVMPort is intentionally
// more permissive so unknown owners still admit (with a warn-log).
func TestIsKnownVMOwnerImpliesIsVMPort(t *testing.T) {
	for _, owner := range []string{
		"compute:nova", "compute:Octavia", "compute:availability-zone-2",
		"Octavia", "Octavia:health-mgr",
		"manila:share", "baremetal:nova", "trunk:subport", "cube:mgr",
	} {
		if !IsVMPort(owner) {
			t.Errorf("IsKnownVMOwner(%q)=true but IsVMPort(%q)=false (catalogue must be a subset)",
				owner, owner)
		}
	}
}

// TestPortClassPartition asserts the two predicates partition the
// observed `device_owner` space — every value lands in exactly one
// of {infra, VM, neither}.
func TestPortClassPartition(t *testing.T) {
	for _, owner := range []string{
		"compute:nova", "Octavia", "manila:share", "baremetal:nova", "cube:mgr",
		"network:router_interface", "network:dhcp", "network:floatingip",
		"network:remote_managed", "",
	} {
		infra := IsInfraPort(owner)
		vm := IsVMPort(owner)
		if infra && vm {
			t.Errorf("device_owner=%q classified as BOTH infra and VM", owner)
		}
	}
}

func TestIsInfraPort(t *testing.T) {
	tests := []struct {
		deviceOwner string
		want        bool
	}{
		{"network:router_interface", true},
		{"network:router_gateway", true},
		{"network:dhcp", true},
		{"network:metadata", true},
		{"network:distributed", true},
		{"network:floatingip_agent_gateway", true},
		{"network:ha_router_replicated_interface", true},
		{"network:routed", true},
		{"network:floatingip", false}, // explicit exception
		{"compute:nova", false},
		{"compute:Octavia", false},
		{"Octavia", false},
		{"manila:share", false},
		{"baremetal:nova", false},
		{"trunk:subport", false},
		{"", false},
	}
	for _, tc := range tests {
		if got := IsInfraPort(tc.deviceOwner); got != tc.want {
			t.Errorf("IsInfraPort(%q) = %v, want %v", tc.deviceOwner, got, tc.want)
		}
	}
}
