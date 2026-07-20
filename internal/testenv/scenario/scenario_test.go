package scenario

import (
	"strings"
	"testing"
)

// TestNIC_SharesServerIdentity: an extra NIC is a second compute port
// under the SAME DeviceID as the VM's primary port (so realize boots
// one server), on the NIC's own network/subnet, owning project
// inherited from the VM.
func TestNIC_SharesServerIdentity(t *testing.T) {
	b := New()
	b.Network("net-a", "T1").Subnet("sub-a", "10.0.1.0/24", "10.0.1.1").VM("vm-a", "T1", "10.0.1.5")
	b.Network("net-b", "T1").Subnet("sub-b", "10.0.2.0/24", "10.0.2.1")
	b.NIC("vm-a", "sub-b", "10.0.2.9")
	snap := b.Build()

	var prim, extra bool
	for _, p := range snap.Ports {
		if p.DeviceID != "vm-a-instance" {
			continue
		}
		if p.ID == "vm-a" {
			prim = true
			if p.NetworkID != "net-a" {
				t.Errorf("primary NIC network = %q, want net-a", p.NetworkID)
			}
			continue
		}
		extra = true
		if !strings.HasPrefix(p.ID, "vm-a-nic-") {
			t.Errorf("extra NIC id = %q, want vm-a-nic-* ", p.ID)
		}
		if p.NetworkID != "net-b" {
			t.Errorf("extra NIC network = %q, want net-b", p.NetworkID)
		}
		if p.ProjectID != "T1" {
			t.Errorf("extra NIC project = %q, want T1 (inherited)", p.ProjectID)
		}
		if p.DeviceOwner != "compute:nova" {
			t.Errorf("extra NIC device_owner = %q, want compute:nova", p.DeviceOwner)
		}
		if len(p.FixedIPs) != 1 || p.FixedIPs[0].IPAddress != "10.0.2.9" || p.FixedIPs[0].SubnetID != "sub-b" {
			t.Errorf("extra NIC fixed IP wrong: %+v", p.FixedIPs)
		}
	}
	if !prim || !extra {
		t.Fatalf("want both the primary and the extra NIC under vm-a-instance (primary=%v extra=%v)", prim, extra)
	}
}

func TestNIC_UnknownVMPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("NIC on an undeclared VM must panic")
		}
	}()
	b := New()
	b.Network("net-b", "T1").Subnet("sub-b", "10.0.2.0/24", "10.0.2.1")
	b.NIC("ghost", "sub-b", "10.0.2.9")
}
