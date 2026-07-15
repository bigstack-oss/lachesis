package scenariotest

import (
	"context"
	"fmt"
	"io"
	"time"
)

// DriveOptions bundles everything `drive` needs to push a scenario's
// declared flows across the realized topology.
type DriveOptions struct {
	Config    Config
	Scenario  *Scenario
	State     *RunState
	StatePath string
	Metrics   MetricsSource
	Exec      VMExec
	Log       io.Writer

	// SinkDelay is the pause between starting a flow's sink and
	// streaming into it, giving the listener time to bind. Zero uses
	// [defaultSinkDelay]; tests set a negative value to skip.
	SinkDelay time.Duration
	// ReadyTimeout bounds the per-VM SSH-readiness wait. Zero uses
	// [defaultReadyTimeout].
	ReadyTimeout time.Duration
}

const (
	// defaultSinkDelay gives a just-started busybox `nc -l` a moment
	// to bind before the stream dials it.
	defaultSinkDelay = 2 * time.Second
	// defaultReadyTimeout bounds how long drive waits for a VM to
	// answer SSH. ACTIVE (Nova) precedes SSH-ready (cloud-init +
	// dropbear) by tens of seconds on a real cluster.
	defaultReadyTimeout = 120 * time.Second
	// readyPollInterval is the pause between SSH-readiness probes.
	readyPollInterval = 5 * time.Second
	// flowBasePort is the sink port for flow 0; flow i listens on
	// flowBasePort+i so concurrent-run leftovers never collide.
	flowBasePort = 15000
	// pingPayloadBytes is the ICMP payload size for external-target
	// flows. The byte math treats headers as free margin, so MinBytes
	// stays a safe lower bound. Sized so a MiB-scale budget fits the
	// SSH exec timeout: busybox ping has no sub-second interval flag,
	// so the packet count is the duration in seconds — 60 KB payloads
	// (kernel-fragmented on the wire; every fragment's bytes still
	// count at the tap) push 1 MiB in ~18 packets instead of the 1024
	// one-per-second packets that killed the exec budget.
	pingPayloadBytes = 60000
)

// Drive pushes every declared flow across the realized topology: it
// re-confirms the attach gate recorded by `up`, snapshots the
// pre-traffic lachesis_bytes_total baseline into the run-state (assert
// diffs against it), then executes the flows in declaration order.
//
// Flow strategies (both busybox/Cirros-safe, both validated live):
//   - VM target: a `nc -l` sink starts on the target (reached via its
//     FIP), then the source streams `dd | nc` at the target's internal
//     IP — so the asserted bytes flow tenant-network paths, not FIPs.
//   - External target: the source pings the literal IP with a sized
//     payload. Transmitted bytes count at the tap whether or not
//     anything answers, which is exactly the tx lower bound the
//     external/infra scenarios assert.
func Drive(ctx context.Context, opts DriveOptions) error {
	if opts.Log == nil {
		opts.Log = io.Discard
	}
	d := &driver{ctx: ctx, opts: opts}

	if err := d.recheckAttach(); err != nil {
		return err
	}
	if err := d.captureBaseline(); err != nil {
		return err
	}
	for i, f := range opts.Scenario.Flows {
		if err := d.runFlow(i, f); err != nil {
			return fmt.Errorf("flow %d (%s → %s%s): %w", i, f.From, f.To.VMID, f.To.IP, err)
		}
	}
	d.logf("drive complete: %d flow(s) pushed", len(opts.Scenario.Flows))
	return nil
}

type driver struct {
	ctx  context.Context
	opts DriveOptions

	ready map[string]bool // VM DSL ids already confirmed SSH-ready
}

// recheckAttach verifies the taps `up` gated on are still attached:
// the summed gauge must still meet the recorded target and the
// failure counter must not have grown. Skipped (with a log line) when
// the run-state predates attach recording.
func (d *driver) recheckAttach() error {
	snap, err := sampleAcross(d.ctx, d.opts.Metrics, agentURLs(d.opts.Config))
	if err != nil {
		return fmt.Errorf("attach recheck scrape: %w", err)
	}
	rec := d.opts.State.Attach
	if rec.Target == 0 {
		d.logf("attach recheck: run-state has no attach record; skipping gauge comparison")
		return nil
	}
	if snap.AttachedInterfaces < rec.Target {
		return fmt.Errorf("attach recheck: attached_interfaces %.0f < recorded target %.0f — taps lost since up", snap.AttachedInterfaces, rec.Target)
	}
	if snap.AttachFailures > rec.Failures {
		return fmt.Errorf("attach recheck: %.0f new TC attach failure(s) since up", snap.AttachFailures-rec.Failures)
	}
	d.logf("attach recheck: ok (attached_interfaces %.0f ≥ %.0f)", snap.AttachedInterfaces, rec.Target)
	return nil
}

// captureBaseline snapshots lachesis_bytes_total across all agents and
// persists it before any traffic, so assert's deltas exclude
// everything that happened before this drive.
func (d *driver) captureBaseline() error {
	snap, err := sampleAcross(d.ctx, d.opts.Metrics, agentURLs(d.opts.Config))
	if err != nil {
		return fmt.Errorf("baseline scrape: %w", err)
	}
	d.opts.State.Baseline = snap.Bytes
	d.opts.State.BaselineServers = snap.Servers
	if err := d.opts.State.Save(d.opts.StatePath); err != nil {
		return err
	}
	d.logf("baseline captured: %d series (%d per-server)", len(snap.Bytes), len(snap.Servers))
	return nil
}

func (d *driver) runFlow(i int, f Flow) error {
	if f.Proto != TCP {
		return fmt.Errorf("only TCP flows are supported (UDP driving is a later slice)")
	}
	srcFIP, err := d.fip(f.From)
	if err != nil {
		return err
	}
	if err := d.waitReady(f.From, srcFIP); err != nil {
		return err
	}

	if f.To.VMID != "" {
		return d.runVMFlow(i, f, srcFIP)
	}
	return d.runExternalFlow(f, srcFIP)
}

// runVMFlow streams Bytes of TCP from the source VM to the target
// VM's internal IP, sinking into a busybox `nc -l` started via the
// target's FIP.
func (d *driver) runVMFlow(i int, f Flow, srcFIP string) error {
	dstFIP, err := d.fip(f.To.VMID)
	if err != nil {
		return err
	}
	dstInternal, err := internalIP(d.opts.Scenario, f.To.VMID)
	if err != nil {
		return err
	}
	if err := d.waitReady(f.To.VMID, dstFIP); err != nil {
		return err
	}

	port := flowBasePort + i
	sink := fmt.Sprintf("nohup sh -c 'nc -l -p %d > /dev/null' >/dev/null 2>&1 &", port)
	if _, err := d.opts.Exec.Run(d.ctx, dstFIP, sink); err != nil {
		return fmt.Errorf("start sink: %w", err)
	}
	d.sleepSinkDelay()

	count := mibCount(f.Bytes)
	stream := fmt.Sprintf("dd if=/dev/zero bs=1M count=%d 2>/dev/null | nc %s %d", count, dstInternal, port)
	if _, err := d.opts.Exec.Run(d.ctx, srcFIP, stream); err != nil {
		return fmt.Errorf("stream: %w", err)
	}
	d.logf("flow %d: %s → %s (%s:%d) %d MiB over TCP", i, f.From, f.To.VMID, dstInternal, port, count)
	return nil
}

// runExternalFlow pushes the flow's byte budget at a literal IP with
// sized pings. Exit 1 (no replies) is tolerated — transmission, not
// the reply, is what the tx assertion needs — but any other failure
// (127 = ping missing from the image, bad address, …) still errors,
// so a broken driver is caught here rather than as a mystifying
// zero-delta at assert.
func (d *driver) runExternalFlow(f Flow, srcFIP string) error {
	count := (f.Bytes + pingPayloadBytes - 1) / pingPayloadBytes
	cmd := fmt.Sprintf("ping -c %d -s %d %s >/dev/null 2>&1 || [ $? -eq 1 ]", count, pingPayloadBytes, f.To.IP)
	if _, err := d.opts.Exec.Run(d.ctx, srcFIP, cmd); err != nil {
		return fmt.Errorf("ping push: %w", err)
	}
	d.logf("flow: %s → %s, %d ping(s) × %d B payload", f.From, f.To.IP, count, pingPayloadBytes)
	return nil
}

// waitReady polls a trivial command until the VM answers SSH. Nova
// ACTIVE races cloud-init by tens of seconds; without this, the first
// flow of a fresh `run` fails spuriously.
func (d *driver) waitReady(vmID, addr string) error {
	if d.ready == nil {
		d.ready = map[string]bool{}
	}
	if d.ready[vmID] {
		return nil
	}
	timeout := d.opts.ReadyTimeout
	if timeout <= 0 {
		timeout = defaultReadyTimeout
	}
	ctx, cancel := context.WithTimeout(d.ctx, timeout)
	defer cancel()
	for {
		if _, err := d.opts.Exec.Run(ctx, addr, "true"); err == nil {
			d.ready[vmID] = true
			d.logf("vm %s ssh-ready at %s", vmID, addr)
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("vm %s (%s) not ssh-ready before deadline: %w", vmID, addr, ctx.Err())
		case <-time.After(readyPollInterval):
		}
	}
}

func (d *driver) sleepSinkDelay() {
	delay := d.opts.SinkDelay
	if delay == 0 {
		delay = defaultSinkDelay
	}
	if delay > 0 {
		time.Sleep(delay)
	}
}

func (d *driver) fip(vmID string) (string, error) {
	for _, f := range d.opts.State.FIPs {
		if f.VMID == vmID {
			return f.Address, nil
		}
	}
	return "", fmt.Errorf("run-state has no FIP for VM %q", vmID)
}

func (d *driver) logf(format string, args ...any) {
	fmt.Fprintf(d.opts.Log, format+"\n", args...)
}

// internalIP resolves a VM's fixed IP from the scenario's topology —
// the same declaration realize created the port from verbatim.
func internalIP(sc *Scenario, vmID string) (string, error) {
	snap := sc.Builder.Build()
	for _, p := range snap.Ports {
		if p.ID == vmID && len(p.FixedIPs) > 0 {
			return p.FixedIPs[0].IPAddress, nil
		}
	}
	return "", fmt.Errorf("scenario declares no fixed IP for VM %q", vmID)
}

// mibCount converts a byte budget to whole `dd bs=1M` blocks,
// rounding up so the pushed bytes always meet the budget.
func mibCount(bytes int64) int64 {
	const mib = 1 << 20
	c := (bytes + mib - 1) / mib
	if c < 1 {
		c = 1
	}
	return c
}

// agentURLs lists every configured agent's /metrics URL.
func agentURLs(cfg Config) []string {
	urls := make([]string, 0, len(cfg.Cluster.Agents))
	for _, a := range cfg.Cluster.Agents {
		urls = append(urls, a.MetricsURL)
	}
	return urls
}
