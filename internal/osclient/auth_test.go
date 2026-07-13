package osclient

import (
	"strings"
	"testing"

	"github.com/gophercloud/gophercloud/v2"
)

func TestEndpointOpts(t *testing.T) {
	tests := []struct {
		name     string
		iface    string
		fallback string
		want     gophercloud.Availability
		wantErr  bool
	}{
		{"explicit internal", "internal", "public", gophercloud.AvailabilityInternal, false},
		{"explicit public", "public", "internal", gophercloud.AvailabilityPublic, false},
		{"explicit admin", "admin", "internal", gophercloud.AvailabilityAdmin, false},
		{"empty falls back", "", "internal", gophercloud.AvailabilityInternal, false},
		{"empty falls back public", "", "public", gophercloud.AvailabilityPublic, false},
		{"invalid", "bogus", "internal", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := Credentials{Interface: tt.iface, Region: "R1"}
			eo, err := c.EndpointOpts(tt.fallback)
			if tt.wantErr {
				if err == nil || !strings.Contains(err.Error(), "invalid interface") {
					t.Fatalf("want invalid-interface error, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("EndpointOpts: %v", err)
			}
			if eo.Availability != tt.want {
				t.Errorf("Availability = %q, want %q", eo.Availability, tt.want)
			}
			if eo.Region != "R1" {
				t.Errorf("Region = %q, want R1", eo.Region)
			}
		})
	}
}

// Authenticate / AuthenticateProject are exercised end-to-end (with a
// Keystone stub) by internal/neutron's client tests, which flow
// through this package; only the pure interface-selection logic is
// unit-tested here.
