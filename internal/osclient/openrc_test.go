package osclient

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// All test passwords below are synthetic placeholders, not real
// secrets. Keeping them obviously fake reduces the chance of a
// reviewer mistaking the fixture for a leaked credential.

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

func TestParseOpenRC_HappyPath(t *testing.T) {
	got, err := ParseOpenRC(writeFixture(t, sampleOpenRC))
	if err != nil {
		t.Fatalf("ParseOpenRC: %v", err)
	}
	want := Credentials{
		AuthURL:       "http://keystone.example:5000/v3",
		Username:      "admin_cli",
		Password:      "test-password-placeholder",
		ProjectName:   "admin",
		UserDomain:    "default",
		ProjectDomain: "default",
	}
	if got != want {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}
}

func TestParseOpenRC_QuotedValues(t *testing.T) {
	content := `
export OS_AUTH_URL="http://keystone.example:5000/v3"
export OS_USERNAME='admin_cli'
export OS_PASSWORD="quoted-pass"
export OS_PROJECT_NAME=admin
`
	got, err := ParseOpenRC(writeFixture(t, content))
	if err != nil {
		t.Fatalf("ParseOpenRC: %v", err)
	}
	if got.AuthURL != "http://keystone.example:5000/v3" {
		t.Errorf("AuthURL = %q (double quotes not stripped)", got.AuthURL)
	}
	if got.Username != "admin_cli" {
		t.Errorf("Username = %q (single quotes not stripped)", got.Username)
	}
	if got.Password != "quoted-pass" {
		t.Errorf("Password = %q", got.Password)
	}
}

// TestParseOpenRC_PasswordWithHash asserts inline `#` is NOT treated
// as a comment marker — passwords with `#` survive intact.
func TestParseOpenRC_PasswordWithHash(t *testing.T) {
	content := `
export OS_AUTH_URL=http://keystone.example:5000/v3
export OS_USERNAME=u
export OS_PASSWORD=ab#cd#ef
export OS_PROJECT_NAME=p
`
	got, err := ParseOpenRC(writeFixture(t, content))
	if err != nil {
		t.Fatalf("ParseOpenRC: %v", err)
	}
	if got.Password != "ab#cd#ef" {
		t.Fatalf("Password = %q, want ab#cd#ef", got.Password)
	}
}

func TestParseOpenRC_Interface(t *testing.T) {
	content := `
export OS_AUTH_URL=http://keystone.example:5000/v3
export OS_USERNAME=u
export OS_PASSWORD=p
export OS_PROJECT_NAME=admin
export OS_INTERFACE=public
`
	got, err := ParseOpenRC(writeFixture(t, content))
	if err != nil {
		t.Fatalf("ParseOpenRC: %v", err)
	}
	if got.Interface != "public" {
		t.Fatalf("Interface = %q, want public", got.Interface)
	}
}

func TestParseOpenRC_DomainDefaults(t *testing.T) {
	content := `
export OS_AUTH_URL=http://keystone.example:5000/v3
export OS_USERNAME=u
export OS_PASSWORD=p
export OS_PROJECT_NAME=admin
`
	got, err := ParseOpenRC(writeFixture(t, content))
	if err != nil {
		t.Fatalf("ParseOpenRC: %v", err)
	}
	if got.UserDomain != "default" || got.ProjectDomain != "default" {
		t.Errorf("missing domain keys should default to \"default\", got %+v", got)
	}
}

func TestParseOpenRC_WithoutExportPrefix(t *testing.T) {
	// Some operator-edited files omit the `export` keyword.
	content := `
OS_AUTH_URL=http://keystone.example:5000/v3
OS_USERNAME=u
OS_PASSWORD=p
OS_PROJECT_NAME=admin
`
	if _, err := ParseOpenRC(writeFixture(t, content)); err != nil {
		t.Fatalf("ParseOpenRC: %v", err)
	}
}

func TestParseOpenRC_MissingRequiredKeys(t *testing.T) {
	// Only OS_USERNAME is present.
	content := `export OS_USERNAME=admin_cli`
	_, err := ParseOpenRC(writeFixture(t, content))
	if err == nil {
		t.Fatal("missing required keys must return an error")
	}
	for _, want := range []string{"OS_AUTH_URL", "OS_PASSWORD", "OS_PROJECT_NAME"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should mention missing %s, got: %v", want, err)
		}
	}
}

func TestParseOpenRC_MalformedLine(t *testing.T) {
	content := `
export OS_AUTH_URL=http://keystone.example:5000/v3
no_equals_here
`
	_, err := ParseOpenRC(writeFixture(t, content))
	if err == nil || !strings.Contains(err.Error(), "no '='") {
		t.Fatalf("malformed line should fail with 'no =' error, got: %v", err)
	}
}

func TestParseOpenRC_MissingFile(t *testing.T) {
	_, err := ParseOpenRC("/no/such/openrc.sh")
	if err == nil {
		t.Fatal("missing file must return error")
	}
}
