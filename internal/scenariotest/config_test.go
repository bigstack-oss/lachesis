package scenariotest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/osclient"
)

// TestLoadConfig_RejectsUnknownKeys pins the strict decoder: a typo'd
// key must be a parse error, not a silently-ignored field that later
// fails validation with a misleading "missing" message.
func TestLoadConfig_RejectsUnknownKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	body := `version: "1"
openstack:
  auth_url: http://k
  username: u
  password: p
  project_name: admin
prerequisites:
  flavour_name: m1.small
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadConfig(path)
	if err == nil || !strings.Contains(err.Error(), "flavour_name") {
		t.Fatalf("want unknown-key error naming flavour_name, got %v", err)
	}
}

func TestConfigValidate(t *testing.T) {
	base := func() Config {
		c := Defaults()
		c.OpenStack = OpenStackCreds{AuthURL: "http://k", Username: "u", Password: "p", ProjectName: "admin"}
		c.Cluster.Agents = []AgentConfig{{Host: "h", MetricsURL: "http://h/metrics"}}
		c.Prerequisites = Prereqs{ImageName: "i", FlavorName: "f", KeypairName: "k", SecGroupName: "s", ExternalNetworkName: "e"}
		c.SSH.KeyPath = "/k"
		return c
	}
	if err := func() error { c := base(); return c.Validate() }(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{"missing flavor", func(c *Config) { c.Prerequisites.FlavorName = "" }},
		{"missing image", func(c *Config) { c.Prerequisites.ImageName = "" }},
		{"missing external net", func(c *Config) { c.Prerequisites.ExternalNetworkName = "" }},
		{"no agents", func(c *Config) { c.Cluster.Agents = nil }},
		{"missing ssh key", func(c *Config) { c.SSH.KeyPath = "" }},
		{"creds both modes", func(c *Config) { c.OpenStack.CredentialsFile = "/tmp/x" }},
		{"creds neither mode", func(c *Config) { c.OpenStack = OpenStackCreds{} }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := base()
			tt.mutate(&c)
			if err := c.Validate(); err == nil {
				t.Errorf("%s: want error, got nil", tt.name)
			}
		})
	}
}

func TestResolveCredentials_OpenRC(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "admin-openrc.sh")
	body := `# admin openrc
export OS_AUTH_URL=http://k:5000/v3
export OS_USERNAME=admin
export OS_PASSWORD="secret#1"
OS_PROJECT_NAME=admin
export OS_REGION_NAME=RegionOne
export OS_INTERFACE=public
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	creds := OpenStackCreds{CredentialsFile: path}
	got, err := creds.ResolveCredentials()
	if err != nil {
		t.Fatalf("ResolveCredentials: %v", err)
	}
	// The shared osclient parser applies the Keystone domain defaults.
	want := osclient.Credentials{
		AuthURL: "http://k:5000/v3", Username: "admin", Password: "secret#1",
		ProjectName: "admin", Region: "RegionOne", Interface: "public",
		UserDomain: "default", ProjectDomain: "default",
	}
	if got != want {
		t.Errorf("parsed creds:\n got %+v\nwant %+v", got, want)
	}
}

func TestResolveCredentials_Inline(t *testing.T) {
	in := OpenStackCreds{AuthURL: "http://k", Username: "u", Password: "p", ProjectName: "admin"}
	got, err := in.ResolveCredentials()
	if err != nil {
		t.Fatal(err)
	}
	want := osclient.Credentials{AuthURL: "http://k", Username: "u", Password: "p", ProjectName: "admin"}
	if got != want {
		t.Errorf("inline creds changed: got %+v want %+v", got, want)
	}
}

func TestResolveCredentials_OpenRCMissingKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad-openrc.sh")
	// No OS_PASSWORD.
	body := "export OS_AUTH_URL=http://k\nexport OS_USERNAME=u\nexport OS_PROJECT_NAME=admin\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := (&OpenStackCreds{CredentialsFile: path}).ResolveCredentials(); err == nil {
		t.Fatal("want error for missing OS_PASSWORD, got nil")
	}
}
