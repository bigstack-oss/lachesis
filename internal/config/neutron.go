package config

import (
	"errors"
	"fmt"
	"path/filepath"
	"time"
)

// NeutronConfig groups settings for the OpenStack Neutron cold-start
// path: Keystone v3 authentication plus the Neutron API client that
// populates the userspace [metadata.ShardedMetadataMap] and kernel
// LPM trie at boot.
//
// Two credential modes — exactly one must be set when [Enabled]:
//
//  1. CredentialsFile: absolute path to an admin-openrc-style shell
//     file (one `export OS_KEY=value` per line). The agent parses
//     the file at boot; the file is the system of record for
//     secrets.
//  2. Inline (AuthURL, Username, Password, ProjectName, …): values
//     are read straight from the YAML. Convenient for tests; not
//     recommended for production deployments.
//
// Enabled defaults to false so the agent still starts on developer
// machines and in the loadtest harness without Keystone reachable.
// Production deployments set Enabled=true and supply credentials.
type NeutronConfig struct {
	// Enabled gates the entire Neutron subsystem. When false, the
	// agent boots without metadata; the metrics Collector emits
	// `tenant_id="unknown"` for every flow. Operators must flip
	// this to true in production.
	Enabled bool `yaml:"enabled"`

	// CredentialsFile is an absolute path to a shell file containing
	// `export OS_AUTH_URL=...`, `export OS_USERNAME=...` etc. Mutually
	// exclusive with the inline credential fields below.
	CredentialsFile string `yaml:"credentials_file"`

	// AuthURL is the Keystone v3 endpoint (e.g.
	// "http://keystone.example:5000/v3"). Inline mode only.
	AuthURL string `yaml:"auth_url"`
	// Username is the Keystone user. Inline mode only.
	Username string `yaml:"username"`
	// Password is the Keystone user's password. Inline mode only —
	// prefer CredentialsFile for production, which keeps the
	// secret out of the agent's YAML.
	Password string `yaml:"password"`
	// ProjectName is the Keystone project this agent authenticates
	// against. Inline mode only.
	ProjectName string `yaml:"project_name"`
	// UserDomain is the Keystone domain holding the user (typical
	// "default"). Inline mode only.
	UserDomain string `yaml:"user_domain"`
	// ProjectDomain is the Keystone domain holding the project
	// (typical "default"). Inline mode only.
	ProjectDomain string `yaml:"project_domain"`
	// Region is the Keystone region the Neutron endpoint is served
	// from. Empty means "any" — Keystone returns the first endpoint
	// matching service=network. Inline mode only.
	Region string `yaml:"region"`
	// Interface selects which endpoint-catalog interface the
	// Authenticator uses to discover the Neutron URL: "public",
	// "internal", or "admin". Empty falls through to the agent's
	// "internal" default. Inline mode only.
	Interface string `yaml:"interface"`

	// RequestTimeout caps a single HTTP call (Keystone auth, Neutron
	// list page). The boot-time retry loop is the unit of total
	// patience, not this timeout.
	RequestTimeout time.Duration `yaml:"request_timeout"`
	// RefreshLead is the amount of time before token expiry at which
	// the agent proactively re-authenticates. 5m is safe for the
	// typical 1h Keystone token; tighten only if your deployment
	// issues shorter-lived tokens.
	RefreshLead time.Duration `yaml:"refresh_lead"`
}

func neutronDefaults() NeutronConfig {
	return NeutronConfig{
		Enabled:        false,
		UserDomain:     "default",
		ProjectDomain:  "default",
		RequestTimeout: 30 * time.Second,
		RefreshLead:    5 * time.Minute,
	}
}

// Validate enforces the two-credential-modes contract and the
// presence of required fields in each mode. When Enabled is false,
// every other field is permitted to be unset.
func (c NeutronConfig) Validate() error {
	if !c.Enabled {
		return nil
	}
	hasFile := c.CredentialsFile != ""
	hasInline := c.AuthURL != "" || c.Username != "" || c.Password != "" || c.ProjectName != ""
	switch {
	case hasFile && hasInline:
		return errors.New("set either credentials_file or inline auth_url/username/password/project_name, not both")
	case !hasFile && !hasInline:
		return errors.New("credentials_file or inline auth_url/username/password/project_name is required when enabled")
	case hasFile:
		if !filepath.IsAbs(c.CredentialsFile) {
			return fmt.Errorf("credentials_file %q must be absolute", c.CredentialsFile)
		}
	default: // inline
		switch {
		case c.AuthURL == "":
			return errors.New("auth_url is required for inline credentials")
		case c.Username == "":
			return errors.New("username is required for inline credentials")
		case c.Password == "":
			return errors.New("password is required for inline credentials")
		case c.ProjectName == "":
			return errors.New("project_name is required for inline credentials")
		}
	}
	if c.RequestTimeout <= 0 {
		return fmt.Errorf("request_timeout %v must be positive", c.RequestTimeout)
	}
	if c.RefreshLead <= 0 {
		return fmt.Errorf("refresh_lead %v must be positive", c.RefreshLead)
	}
	return nil
}
