// Package neutron is the OpenStack metadata cold-start path. It
// owns Keystone v3 authentication (via gophercloud) and the
// Neutron v2.0 API client used by the trie builder. See
// docs/DESIGN.md §5.
package neutron

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/config"
)

// Credentials is the resolved set of Keystone v3 password-auth
// values the agent uses to obtain a project-scoped token. Either
// supplied inline via [config.NeutronConfig] or loaded from an
// admin-openrc-style file by [ParseOpenRC].
type Credentials struct {
	AuthURL       string
	Username      string
	Password      string
	ProjectName   string
	UserDomain    string
	ProjectDomain string
	Region        string
	// Interface is the Keystone endpoint-catalog interface to pick
	// when discovering the Neutron URL: "public", "internal", or
	// "admin". Empty falls through to "internal" — the right
	// default for compute-node agents.
	Interface string
}

// FromConfig resolves Credentials from a [config.NeutronConfig].
// The caller is expected to have run [config.NeutronConfig.Validate]
// already, so the exactly-one-of constraint is asserted rather than
// re-validated.
func FromConfig(c config.NeutronConfig) (Credentials, error) {
	if c.CredentialsFile != "" {
		return ParseOpenRC(c.CredentialsFile)
	}
	return Credentials{
		AuthURL:       c.AuthURL,
		Username:      c.Username,
		Password:      c.Password,
		ProjectName:   c.ProjectName,
		UserDomain:    c.UserDomain,
		ProjectDomain: c.ProjectDomain,
		Region:        c.Region,
		Interface:     c.Interface,
	}, nil
}

// ParseOpenRC loads Credentials from an admin-openrc-style shell
// file. The file is parsed as `export KEY=VALUE` lines, one
// assignment per line. Lines starting with `#` and blank lines are
// ignored. Values surrounded by matching single or double quotes
// are unquoted. Inline `#` comments are NOT stripped — anything that
// looks like a `#` inside a value is kept as part of the value, so
// passwords containing `#` survive intact.
//
// Required keys: OS_AUTH_URL, OS_USERNAME, OS_PASSWORD,
// OS_PROJECT_NAME. Optional: OS_USER_DOMAIN_NAME (default "default"),
// OS_PROJECT_DOMAIN_NAME (default "default"), OS_REGION_NAME,
// OS_INTERFACE. Other OS_* variables in the file (OS_AUTH_TYPE,
// OS_IDENTITY_API_VERSION, …) are ignored — they belong to other
// OpenStack clients and are noise here.
func ParseOpenRC(path string) (Credentials, error) {
	f, err := os.Open(path)
	if err != nil {
		return Credentials{}, fmt.Errorf("openrc: open %s: %w", path, err)
	}
	defer f.Close()

	env := make(map[string]string)
	scanner := bufio.NewScanner(f)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		line = strings.TrimSpace(line)
		eq := strings.IndexByte(line, '=')
		if eq < 0 {
			return Credentials{}, fmt.Errorf("openrc: %s:%d: no '=' in %q", path, lineNo, line)
		}
		key := strings.TrimSpace(line[:eq])
		val := strings.TrimSpace(line[eq+1:])
		val = unquote(val)
		if key == "" {
			return Credentials{}, fmt.Errorf("openrc: %s:%d: empty key", path, lineNo)
		}
		env[key] = val
	}
	if err := scanner.Err(); err != nil {
		return Credentials{}, fmt.Errorf("openrc: read %s: %w", path, err)
	}

	c := Credentials{
		AuthURL:       env["OS_AUTH_URL"],
		Username:      env["OS_USERNAME"],
		Password:      env["OS_PASSWORD"],
		ProjectName:   env["OS_PROJECT_NAME"],
		UserDomain:    env["OS_USER_DOMAIN_NAME"],
		ProjectDomain: env["OS_PROJECT_DOMAIN_NAME"],
		Region:        env["OS_REGION_NAME"],
		Interface:     env["OS_INTERFACE"],
	}
	if c.UserDomain == "" {
		c.UserDomain = defaultDomain
	}
	if c.ProjectDomain == "" {
		c.ProjectDomain = defaultDomain
	}
	if err := c.requireFields(path); err != nil {
		return Credentials{}, err
	}
	return c, nil
}

// requireFields enforces the four mandatory OS_* keys. path is woven
// into the error so the operator sees which file is malformed.
func (c Credentials) requireFields(path string) error {
	var missing []string
	if c.AuthURL == "" {
		missing = append(missing, "OS_AUTH_URL")
	}
	if c.Username == "" {
		missing = append(missing, "OS_USERNAME")
	}
	if c.Password == "" {
		missing = append(missing, "OS_PASSWORD")
	}
	if c.ProjectName == "" {
		missing = append(missing, "OS_PROJECT_NAME")
	}
	if len(missing) > 0 {
		return fmt.Errorf("openrc: %s: missing required keys: %s",
			path, strings.Join(missing, ", "))
	}
	return nil
}

// unquote strips one layer of matching single or double quotes from
// the start and end of s. Used because admin-openrc files commonly
// quote values that contain spaces, even though Keystone fields
// rarely do.
func unquote(s string) string {
	if len(s) >= 2 {
		first, last := s[0], s[len(s)-1]
		if (first == '"' && last == '"') || (first == '\'' && last == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}
