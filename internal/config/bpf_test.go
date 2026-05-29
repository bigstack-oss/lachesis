package config_test

import (
	"strings"
	"testing"

	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/config"
)

func TestBPFValidate(t *testing.T) {
	abs := "/sys/fs/bpf/telemetry"
	cases := []struct {
		name    string
		cfg     config.BPFConfig
		wantErr string // substring; "" means must validate
	}{
		{
			name: "defaults validate",
			cfg:  config.BPFConfig{PinPath: abs, AttachPrefixes: []string{"tap"}},
		},
		{
			name: "empty allowlist is allowed (out-of-band attach)",
			cfg:  config.BPFConfig{PinPath: abs},
		},
		{
			name:    "empty pin path rejected",
			cfg:     config.BPFConfig{},
			wantErr: "pin_path is empty",
		},
		{
			name:    "relative pin path rejected",
			cfg:     config.BPFConfig{PinPath: "relative/path"},
			wantErr: "must be absolute",
		},
		{
			name:    "empty prefix entry rejected",
			cfg:     config.BPFConfig{PinPath: abs, AttachPrefixes: []string{"tap", ""}},
			wantErr: "attach_prefixes[1] is empty",
		},
		{
			name:    "whitespace prefix entry rejected",
			cfg:     config.BPFConfig{PinPath: abs, AttachPrefixes: []string{"  "}},
			wantErr: "attach_prefixes[0] is empty",
		},
		{
			name:    "empty interface entry rejected",
			cfg:     config.BPFConfig{PinPath: abs, AttachInterfaces: []string{"eth1", ""}},
			wantErr: "attach_interfaces[1] is empty",
		},
		{
			name: "valid prefixes and interfaces validate",
			cfg:  config.BPFConfig{PinPath: abs, AttachPrefixes: []string{"tap", "qvb"}, AttachInterfaces: []string{"eth1"}},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.cfg.Validate()
			if c.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Validate() = nil, want error containing %q", c.wantErr)
			}
			if !strings.Contains(err.Error(), c.wantErr) {
				t.Errorf("Validate() = %q, want substring %q", err, c.wantErr)
			}
		})
	}
}
