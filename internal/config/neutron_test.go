package config_test

import (
	"strings"
	"testing"
	"time"

	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/config"
)

func TestNeutronValidate_DisabledIsAlwaysOK(t *testing.T) {
	c := config.NeutronConfig{Enabled: false}
	if err := c.Validate(); err != nil {
		t.Fatalf("disabled neutron must validate, got %v", err)
	}
}

func TestNeutronValidate(t *testing.T) {
	enabledFile := config.NeutronConfig{
		Enabled:         true,
		CredentialsFile: "/etc/admin-openrc.sh",
		UserDomain:      "default",
		ProjectDomain:   "default",
		RequestTimeout:  30 * time.Second,
		RefreshLead:     5 * time.Minute,
	}
	enabledInline := config.NeutronConfig{
		Enabled:        true,
		AuthURL:        "http://keystone.example:5000/v3",
		Username:       "admin_cli",
		Password:       "secret",
		ProjectName:    "admin",
		UserDomain:     "default",
		ProjectDomain:  "default",
		RequestTimeout: 30 * time.Second,
		RefreshLead:    5 * time.Minute,
	}

	cases := []struct {
		name      string
		cfg       config.NeutronConfig
		wantOK    bool
		errSubstr string
	}{
		{"file mode valid", enabledFile, true, ""},
		{"inline mode valid", enabledInline, true, ""},
		{"both modes set", func() config.NeutronConfig {
			c := enabledFile
			c.AuthURL = "http://keystone.example:5000/v3"
			return c
		}(), false, "not both"},
		{"neither set", func() config.NeutronConfig {
			c := enabledFile
			c.CredentialsFile = ""
			return c
		}(), false, "required"},
		{"relative credentials_file", func() config.NeutronConfig {
			c := enabledFile
			c.CredentialsFile = "etc/admin-openrc.sh"
			return c
		}(), false, "absolute"},
		{"inline missing auth_url", func() config.NeutronConfig {
			c := enabledInline
			c.AuthURL = ""
			return c
		}(), false, "auth_url"},
		{"inline missing username", func() config.NeutronConfig {
			c := enabledInline
			c.Username = ""
			return c
		}(), false, "username"},
		{"inline missing password", func() config.NeutronConfig {
			c := enabledInline
			c.Password = ""
			return c
		}(), false, "password"},
		{"inline missing project_name", func() config.NeutronConfig {
			c := enabledInline
			c.ProjectName = ""
			return c
		}(), false, "project_name"},
		{"zero request_timeout", func() config.NeutronConfig {
			c := enabledFile
			c.RequestTimeout = 0
			return c
		}(), false, "request_timeout"},
		{"zero refresh_lead", func() config.NeutronConfig {
			c := enabledFile
			c.RefreshLead = 0
			return c
		}(), false, "refresh_lead"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate()
			switch {
			case tc.wantOK && err != nil:
				t.Fatalf("want OK, got %v", err)
			case !tc.wantOK && err == nil:
				t.Fatal("want error, got nil")
			case !tc.wantOK && !strings.Contains(err.Error(), tc.errSubstr):
				t.Fatalf("error should mention %q, got: %v", tc.errSubstr, err)
			}
		})
	}
}

func TestNeutronEnvAndFlagOverride(t *testing.T) {
	clearEnv(t)
	t.Setenv("CUBECOS_NEUTRON_ENABLED", "true")
	t.Setenv("CUBECOS_NEUTRON_CREDENTIALS_FILE", "/etc/admin-openrc.sh")

	cfg, err := config.Load(config.Options{}, nil)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.Neutron.Enabled {
		t.Errorf("Neutron.Enabled = false, want true (env override)")
	}
	if cfg.Neutron.CredentialsFile != "/etc/admin-openrc.sh" {
		t.Errorf("Neutron.CredentialsFile = %q, want /etc/admin-openrc.sh", cfg.Neutron.CredentialsFile)
	}

	// Flag should override env.
	cfg, err = config.Load(config.Options{}, []string{
		"-neutron-credentials-file", "/run/secrets/openrc",
	})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Neutron.CredentialsFile != "/run/secrets/openrc" {
		t.Errorf("flag override failed: got %q", cfg.Neutron.CredentialsFile)
	}
}
