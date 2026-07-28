// Traffic steps: pushing bytes between the realized VMs and
// snapshotting the counters that measure them.

package steps

import (
	"context"
	"fmt"
	"io"

	"github.com/bigstack-oss/lachesis/internal/scenariotest"
	"github.com/bigstack-oss/lachesis/internal/scenariotest/assert"
	"github.com/bigstack-oss/lachesis/internal/scenariotest/drive"
	"github.com/bigstack-oss/lachesis/internal/scenariotest/gate"
)

// DriveStep pushes Flows exactly like the standalone `drive`
// subcommand: attach recheck, fresh baseline into run-state, then the
// streams. A later [AssertStep] diffs against this step's baseline.
type DriveStep struct {
	Flows []scenariotest.Flow
	// KeepBaseline drives without resetting the run-state baseline, so a
	// following [AssertStep] measures the CUMULATIVE delta since an
	// earlier drive — the way router-regateway proves a second drive's
	// live bytes ADD to the settled total (settled + live) rather than
	// starting from zero.
	KeepBaseline bool
	// SkipMACLearn drives without the pre-drive MAC-learn gate — for the
	// unresolved-latebind scenario, where a VM's MAC is deliberately not
	// yet learned so its first bytes must park unknown. Leave false
	// everywhere else.
	SkipMACLearn bool
	// SkipAttachRecheck drives without re-confirming the up-time attach
	// gate — for a drive that follows a tap teardown (ghost-grace deletes
	// the peer, dropping a tap and racing a benign attach-failure).
	SkipAttachRecheck bool
}

func (DriveStep) Kind() string { return "drive" }

func (s DriveStep) Run(ctx context.Context, env *scenariotest.StepEnv) error {
	sc := *env.Scenario
	sc.Flows = s.Flows
	return drive.Run(ctx, drive.Options{
		Config:            env.Config,
		Scenario:          &sc,
		State:             env.State,
		StatePath:         env.StatePath,
		Metrics:           env.Metrics,
		Exec:              env.Exec,
		Log:               env.Log,
		SinkDelay:         env.SinkDelay,
		MACLearnTimeout:   env.MACLearnTimeout,
		KeepBaseline:      s.KeepBaseline,
		SkipMACLearn:      s.SkipMACLearn,
		SkipAttachRecheck: s.SkipAttachRecheck,
	})
}

// IngressFlowStep streams Bytes INTO a VM from the harness itself —
// the "sender outside the cluster" no [scenariotest.Flow] can express, and the
// only way to drive the external/rx tuple through the FIP DNAT path
// (docs/architecture/edge-cases.md). It runs drive's usual gates
// (attach recheck, MAC-learn, fresh baseline — a later [AssertStep]
// diffs against it), then feeds the byte budget over SSH stdin into a
// `cat > /dev/null` on the VM: SSH because its port is the one
// inbound path the platform security group is guaranteed to pass (the
// harness already reaches every VM through it). The stream framing
// only adds bytes on the wire, so MinBytes = Bytes stays a safe lower
// bound.
type IngressFlowStep struct {
	// To is the DSL VM id receiving the stream, dialed at its FIP.
	To    string
	Bytes int64
}

func (IngressFlowStep) Kind() string { return "ingress-flow" }

func (s IngressFlowStep) Run(ctx context.Context, env *scenariotest.StepEnv) error {
	stdin, ok := env.Exec.(scenariotest.StdinExec)
	if !ok {
		return fmt.Errorf("ingress-flow: the exec transport cannot stream stdin (need [scenariotest.StdinExec])")
	}
	// Zero-flow drive: the same gates and baseline capture a DriveStep
	// gets, with the actual traffic pushed from the harness below.
	sc := *env.Scenario
	sc.Flows = nil
	if err := drive.Run(ctx, drive.Options{
		Config:          env.Config,
		Scenario:        &sc,
		State:           env.State,
		StatePath:       env.StatePath,
		Metrics:         env.Metrics,
		Exec:            env.Exec,
		Log:             env.Log,
		SinkDelay:       env.SinkDelay,
		MACLearnTimeout: env.MACLearnTimeout,
	}); err != nil {
		return err
	}
	fip := ""
	for _, f := range env.State.FIPs {
		if f.VMID == s.To && f.Network == "" { // the provider SSH FIP
			fip = f.Address
		}
	}
	if fip == "" {
		return fmt.Errorf("ingress-flow: run-state has no SSH FIP for VM %q", s.To)
	}
	if err := gate.SSHReady(ctx, env, s.To, fip); err != nil {
		return fmt.Errorf("ingress-flow: %w", err)
	}
	if out, err := stdin.RunWithStdin(ctx, fip, "cat > /dev/null", io.LimitReader(zeroReader{}, s.Bytes)); err != nil {
		return fmt.Errorf("ingress-flow: stream %d bytes to %s: %w (output: %s)", s.Bytes, s.To, err, out)
	}
	env.Log.Info("ingress-flow: streamed", "to", s.To, "fip", fip, "bytes", s.Bytes)
	return nil
}

// zeroReader is an endless stream of zero bytes; [IngressFlowStep]
// bounds it with io.LimitReader.
type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

// AssertStep evaluates scenariotest.Expect with the stabilize-polling `assert`
// semantics against the most recent DriveStep's baseline, folding the
// rows (tagged Note when they carry none) into the run's report.
type AssertStep struct {
	Expect []scenariotest.Expect
	Note   string
}

func (AssertStep) Kind() string { return "assert" }

func (s AssertStep) Run(ctx context.Context, env *scenariotest.StepEnv) error {
	sc := *env.Scenario
	sc.Expect = s.Expect
	rep, err := assert.Run(ctx, assert.Options{
		Config:     env.Config,
		Scenario:   &sc,
		State:      env.State,
		ReportPath: env.ReportPath,
		Metrics:    env.Metrics,
		Log:        env.Log,
	})
	if err != nil {
		return err
	}
	for _, row := range rep.Rows {
		if row.Note == "" {
			row.Note = s.Note
		}
		env.AddRow(row)
	}
	return nil
}

// CaptureStep snapshots every counter tuple plus the settled-flows
// base. Monotone and growth assertions, and the sweep wait, diff
// against the most recent capture.
type CaptureStep struct{}

func (CaptureStep) Kind() string { return "capture" }

func (CaptureStep) Run(ctx context.Context, env *scenariotest.StepEnv) error {
	return env.TakeCapture(ctx)
}
