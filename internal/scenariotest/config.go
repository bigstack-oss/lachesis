package scenariotest

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/bigstack-oss/lachesis/internal/osclient"
)

// Config is the on-disk YAML scenariotest consumes. Mirrors the
// agent's two-mode credential pattern: either credentials_file
// (admin-openrc-style) or inline auth_url / username / password /
// project_name / domains / region / interface. The credentials must
// be admin-scoped — reuse-or-create projects and host-pinned
// placement both require it.
//
// Resolution order: built-in defaults → YAML → validate. Mirrors the
// agent's two-mode credential pattern but stays YAML-centric (no env
// or flag layering) since scenariotest is an operator-run harness,
// not a long-lived service.
type Config struct {
	Version       string             `yaml:"version"`
	OpenStack     OpenStackCreds     `yaml:"openstack"`
	Cluster       ClusterConfig      `yaml:"cluster"`
	Prerequisites Prereqs            `yaml:"prerequisites"`
	SSH           SSHConfig          `yaml:"ssh"`
	AgentControl  AgentControlConfig `yaml:"agent_control"`
	Naming        NamingConfig       `yaml:"naming"`
}

// OpenStackCreds holds Keystone credentials. Exactly one of
// CredentialsFile or the inline (AuthURL+Username+Password+
// ProjectName) set must be populated.
type OpenStackCreds struct {
	CredentialsFile string `yaml:"credentials_file"`

	AuthURL       string `yaml:"auth_url"`
	Username      string `yaml:"username"`
	Password      string `yaml:"password"`
	ProjectName   string `yaml:"project_name"`
	UserDomain    string `yaml:"user_domain"`
	ProjectDomain string `yaml:"project_domain"`
	Region        string `yaml:"region"`
	Interface     string `yaml:"interface"`

	RequestTimeout time.Duration `yaml:"request_timeout"`
}

// ClusterConfig describes the live cluster scenariotest drives. Name
// is informational. Agents lists every compute node whose /metrics
// scenariotest may need to scrape — for single-node dev-cmp that's
// one entry; for cc that's three.
type ClusterConfig struct {
	Name   string        `yaml:"name"`
	Agents []AgentConfig `yaml:"agents"`
}

// AgentConfig pairs a hypervisor name (as it appears in the Nova
// hypervisor list and in [Scenario.Placement]) with the URL where
// that compute node's agent exposes /metrics. SSHHost is the address
// [RestartAgentStep] connects to for that node's agent host; empty
// means use Host (correct when the hypervisor name resolves and is
// SSH-reachable, e.g. single-node dev-cmp).
type AgentConfig struct {
	Host       string `yaml:"host"`
	MetricsURL string `yaml:"metrics_url"`
	SSHHost    string `yaml:"ssh_host"`
}

// sshHost is the address [RestartAgentStep] SSHes to for this agent —
// the explicit ssh_host, else the hypervisor Host.
func (a AgentConfig) sshHost() string {
	if a.SSHHost != "" {
		return a.SSHHost
	}
	return a.Host
}

// AgentControlConfig is how [RestartAgentStep] reaches and restarts the
// telemetry agent on a compute host: an SSH transport to the agent
// hosts — deliberately separate from [SSHConfig], which is the in-VM
// traffic driver (different user, key, and target: the agent host is
// typically root@compute, the VMs are the image's default user) — plus
// the systemd unit it acts on. Optional: only [RestartAgentStep] reads
// it, so scenarios that never restart an agent leave it unset.
type AgentControlConfig struct {
	User    string        `yaml:"user"`
	KeyPath string        `yaml:"key_path"`
	Timeout time.Duration `yaml:"timeout"`
	// Unit is the systemd unit to restart; defaults to "lachesis-agent".
	Unit string `yaml:"unit"`
	// ConfigPath is the agent config file the unit reads —
	// [RestartAgentStep]'s SetConfig derives its overrides from this file
	// and writes them back here. Only needed by scenarios that change the
	// agent's config.
	ConfigPath string `yaml:"config_path"`
	// ReadyTimeout bounds the post-restart wait for /metrics to answer
	// and the taps to re-attach; defaults to [DefaultAgentReadyTimeout].
	ReadyTimeout time.Duration `yaml:"ready_timeout"`
	// WALPath is the agent's on-host WAL file — only needed by
	// cold-restart scenarios ([RestartAgentStep].RemoveWAL deletes it
	// and its .bak between stop and start).
	WALPath string `yaml:"wal_path"`
	// PinPath is the agent's bpffs pin directory — only needed by
	// cold-restart scenarios ([RestartAgentStep].RemovePins removes it
	// to simulate a host reboot's kernel-state loss).
	PinPath string `yaml:"pin_path"`
}

// SSHConfig projects the agent-control block onto the shared
// [SSHConfig] shape so the CLI can build the agent-host [SSHExec] the
// same way it builds the VM driver's.
func (a AgentControlConfig) SSHConfig() SSHConfig {
	return SSHConfig{User: a.User, KeyPath: a.KeyPath, Timeout: a.Timeout}
}

// Prereqs names the pre-staged Glance / Nova / Neutron resources
// scenariotest expects to find at preflight. The tool checks
// existence and refuses to run if any are missing — it never
// creates these.
type Prereqs struct {
	ImageName           string `yaml:"image_name"`
	FlavorName          string `yaml:"flavor_name"`
	KeypairName         string `yaml:"keypair_name"`
	SecGroupName        string `yaml:"secgroup_name"`
	ExternalNetworkName string `yaml:"external_network_name"`
}

// SSHConfig is the in-VM traffic driver's SSH transport.
// KeyPath must reference a key whose public half is registered as
// Prereqs.KeypairName in Nova.
type SSHConfig struct {
	User    string        `yaml:"user"`
	KeyPath string        `yaml:"key_path"`
	Timeout time.Duration `yaml:"timeout"`
}

// NamingConfig controls the prefix mangled into every created
// Neutron/Nova resource: "<prefix>-<run-id>-<dsl-id>". Projects
// receive the same prefix.
type NamingConfig struct {
	Prefix string `yaml:"prefix"`
}

// Defaults returns a Config populated with the built-in defaults.
// Callers layer YAML on top before validation.
func Defaults() Config {
	return Config{
		Version: "1",
		OpenStack: OpenStackCreds{
			UserDomain:     "default",
			ProjectDomain:  "default",
			RequestTimeout: 30 * time.Second,
		},
		SSH: SSHConfig{
			User:    "ubuntu",
			Timeout: 60 * time.Second,
		},
		AgentControl: AgentControlConfig{
			User:         "root",
			Timeout:      30 * time.Second,
			Unit:         "lachesis-agent",
			ReadyTimeout: DefaultAgentReadyTimeout,
		},
		Naming: NamingConfig{Prefix: "scenariotest"},
	}
}

// LoadConfig reads path as YAML, merges it over [Defaults], and
// validates the result. The returned Config is ready to hand to
// preflight / realize / etc.
func LoadConfig(path string) (Config, error) {
	cfg := Defaults()
	raw, err := os.ReadFile(path)
	if err != nil {
		return cfg, fmt.Errorf("read config %s: %w", path, err)
	}
	// KnownFields makes a typo'd key (e.g. flavour_name) a parse error
	// instead of a silently-ignored field — same strictness as the
	// agent's config loader.
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return cfg, fmt.Errorf("parse config %s: %w", path, err)
	}
	if err := cfg.Validate(); err != nil {
		return cfg, fmt.Errorf("invalid config %s: %w", path, err)
	}
	return cfg, nil
}

// Validate checks the cross-field invariants. Returns the first
// problem found.
func (c *Config) Validate() error {
	if c.Version != "1" {
		return fmt.Errorf("version: want \"1\", got %q", c.Version)
	}
	if err := c.OpenStack.validate(); err != nil {
		return fmt.Errorf("openstack: %w", err)
	}
	if len(c.Cluster.Agents) == 0 {
		return fmt.Errorf("cluster.agents: at least one entry required")
	}
	for i, a := range c.Cluster.Agents {
		if a.Host == "" {
			return fmt.Errorf("cluster.agents[%d].host: required", i)
		}
		if a.MetricsURL == "" {
			return fmt.Errorf("cluster.agents[%d].metrics_url: required", i)
		}
	}
	if c.Prerequisites.ImageName == "" {
		return fmt.Errorf("prerequisites.image_name: required")
	}
	if c.Prerequisites.FlavorName == "" {
		return fmt.Errorf("prerequisites.flavor_name: required")
	}
	if c.Prerequisites.KeypairName == "" {
		return fmt.Errorf("prerequisites.keypair_name: required")
	}
	if c.Prerequisites.SecGroupName == "" {
		return fmt.Errorf("prerequisites.secgroup_name: required")
	}
	if c.Prerequisites.ExternalNetworkName == "" {
		return fmt.Errorf("prerequisites.external_network_name: required")
	}
	if c.SSH.KeyPath == "" {
		return fmt.Errorf("ssh.key_path: required")
	}
	if c.Naming.Prefix == "" {
		return fmt.Errorf("naming.prefix: required")
	}
	return nil
}

func (o *OpenStackCreds) validate() error {
	inlineSet := o.AuthURL != "" || o.Username != "" || o.Password != "" || o.ProjectName != ""
	if o.CredentialsFile != "" && inlineSet {
		return fmt.Errorf("credentials_file and inline credentials are mutually exclusive")
	}
	if o.CredentialsFile == "" && !inlineSet {
		return fmt.Errorf("either credentials_file or inline auth_url/username/password/project_name required")
	}
	if o.CredentialsFile != "" {
		expanded := expandHome(o.CredentialsFile)
		if _, err := os.Stat(expanded); err != nil {
			return fmt.Errorf("credentials_file %s: %w", o.CredentialsFile, err)
		}
	}
	return nil
}

// ResolveCredentials resolves this two-mode credential block to the
// shared [osclient.Credentials]: CredentialsFile (when set) is parsed
// by [osclient.ParseOpenRC] — the same parser the agent uses — and
// the inline fields copy over otherwise.
func (o *OpenStackCreds) ResolveCredentials() (osclient.Credentials, error) {
	if o.CredentialsFile != "" {
		return osclient.ParseOpenRC(expandHome(o.CredentialsFile))
	}
	return osclient.Credentials{
		AuthURL:       o.AuthURL,
		Username:      o.Username,
		Password:      o.Password,
		ProjectName:   o.ProjectName,
		UserDomain:    o.UserDomain,
		ProjectDomain: o.ProjectDomain,
		Region:        o.Region,
		Interface:     o.Interface,
	}, nil
}

func expandHome(p string) string {
	if !strings.HasPrefix(p, "~/") {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return p
	}
	return filepath.Join(home, p[2:])
}
