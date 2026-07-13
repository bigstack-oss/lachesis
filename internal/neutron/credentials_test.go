package neutron

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/config"
)

// The openrc parser itself is tested in internal/osclient; the tests
// here cover only this package's mapping from [config.NeutronConfig].
// The password below is a synthetic placeholder, not a real secret.

const sampleOpenRC = `# CubeCOS test fixture — fake credentials.
export OS_AUTH_TYPE=password
export OS_USERNAME=admin_cli
export OS_PASSWORD=test-password-placeholder
export OS_PROJECT_NAME=admin
export OS_USER_DOMAIN_NAME=default
export OS_PROJECT_DOMAIN_NAME=default
export OS_AUTH_URL=http://keystone.example:5000/v3
export OS_IDENTITY_API_VERSION=3
export OS_IMAGE_API_VERSION=2
`

func writeFixture(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "openrc.sh")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return path
}

func TestFromConfig_File(t *testing.T) {
	path := writeFixture(t, sampleOpenRC)
	got, err := FromConfig(config.NeutronConfig{
		Enabled:         true,
		CredentialsFile: path,
		RequestTimeout:  30 * time.Second,
		RefreshLead:     5 * time.Minute,
	})
	if err != nil {
		t.Fatalf("FromConfig: %v", err)
	}
	if got.AuthURL != "http://keystone.example:5000/v3" || got.Username != "admin_cli" {
		t.Fatalf("file path not honoured: %+v", got)
	}
}

func TestFromConfig_Inline(t *testing.T) {
	c := config.NeutronConfig{
		Enabled:        true,
		AuthURL:        "http://keystone.example:5000/v3",
		Username:       "u",
		Password:       "p",
		ProjectName:    "admin",
		UserDomain:     "Default",
		ProjectDomain:  "Default",
		Region:         "RegionOne",
		RequestTimeout: 30 * time.Second,
		RefreshLead:    5 * time.Minute,
	}
	got, err := FromConfig(c)
	if err != nil {
		t.Fatalf("FromConfig: %v", err)
	}
	want := Credentials{
		AuthURL:       c.AuthURL,
		Username:      c.Username,
		Password:      c.Password,
		ProjectName:   c.ProjectName,
		UserDomain:    c.UserDomain,
		ProjectDomain: c.ProjectDomain,
		Region:        c.Region,
	}
	if got != want {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}
}
