package scenariotest

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
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
	Log       *slog.Logger

	// SinkDelay is the pause between starting a flow's sink and
	// streaming into it, giving the listener time to bind. Zero uses
	// [defaultSinkDelay]; tests set a negative value to skip.
	SinkDelay time.Duration
	// MACLearnTimeout bounds the pre-drive MAC-learn gate. Zero uses
	// [DefaultMACLearnTimeout]; tests set a small value.
	MACLearnTimeout time.Duration
	// ReadyTimeout bounds the per-VM SSH-readiness wait. Zero uses
	// [defaultReadyTimeout].
	ReadyTimeout time.Duration
	// KeepBaseline drives WITHOUT snapshotting a fresh pre-traffic
	// baseline, so a later [AssertStep] measures the CUMULATIVE delta from
	// an earlier drive's baseline rather than just this drive's. Used to
	// prove traffic ADDS to an existing (e.g. settled) total — the
	// round-trip router-regateway drives a second time with this set so
	// the assert sees settled + live, not just live.
	KeepBaseline bool
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

	// DefaultMACLearnTimeout bounds the pre-drive MAC-learn gate. The
	// agents learn a new port when Kafka kicks the reconciler (seconds)
	// or the 5-minute periodic pass runs — same no-Kafka ceiling
	// reasoning as [DefaultAnomalyTimeout].
	DefaultMACLearnTimeout = 8 * time.Minute
	// macLearnPollInterval is the pause between MAC-learn gate polls
	// (shrunk proportionally when the configured timeout is small).
	macLearnPollInterval = 3 * time.Second
)

// Drive pushes every declared flow across the realized topology: it
// re-confirms the attach gate recorded by `up`, snapshots the
// pre-traffic lachesis_tenant_bytes_total baseline into the run-state (assert
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
		opts.Log = slog.New(slog.DiscardHandler)
	}
	d := &driver{ctx: ctx, opts: opts}

	if err := d.recheckAttach(); err != nil {
		return err
	}
	if err := d.waitMACsLearned(); err != nil {
		return err
	}
	if opts.KeepBaseline {
		opts.Log.Info("baseline kept from a prior drive (cumulative measurement)")
	} else if err := d.captureBaseline(); err != nil {
		return err
	}
	for i, f := range opts.Scenario.Flows {
		if err := d.runFlow(i, f); err != nil {
			return fmt.Errorf("flow %d (%s → %s%s): %w", i, f.From, f.To.VMID, f.To.IP, err)
		}
	}
	d.opts.Log.Info("drive complete", "flows", len(opts.Scenario.Flows))
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
	snap, err := sampleAcross(d.ctx, d.opts.Metrics, d.opts.Config.Cluster.Agents)
	if err != nil {
		return fmt.Errorf("attach recheck scrape: %w", err)
	}
	rec := d.opts.State.Attach
	if rec.Target == 0 {
		d.opts.Log.Warn("attach recheck: run-state has no attach record; skipping gauge comparison")
		return nil
	}
	if snap.AttachedInterfaces < rec.Target {
		return fmt.Errorf("attach recheck: attached_interfaces %.0f < recorded target %.0f — taps lost since up", snap.AttachedInterfaces, rec.Target)
	}
	if snap.AttachFailures > rec.Failures {
		return fmt.Errorf("attach recheck: %.0f new TC attach failure(s) since up", snap.AttachFailures-rec.Failures)
	}
	d.opts.Log.Info("attach recheck: ok", "attached", snap.AttachedInterfaces, "target", rec.Target)
	return nil
}

// waitMACsLearned gates the drive on every created VM MAC being
// resolvable by EVERY configured agent — the fix for the learning race
// where traffic pushed before the agents' maps know a just-created
// port classifies as zone="miss" forever (dst_zone is baked into the
// flow key at packet time). Multi-agent because zone classification
// needs the PEER's MAC on the peer VM's node, not just the local one.
// Skips (with a log line) when the run-state predates MAC recording.
func (d *driver) waitMACsLearned() error {
	var want []ResourceRef
	for _, p := range d.opts.State.Ports {
		// Router-interface MACs are deliberately never in
		// mac_tenant_map — gating on them would wait forever. Their
		// MACs are recorded for [AssertFlowPeerStep], not for us.
		if p.MAC != "" && !p.RouterInterface {
			want = append(want, p)
		}
	}
	if len(want) == 0 {
		d.opts.Log.Warn("mac-learn gate: run-state records no port MACs; skipping")
		return nil
	}
	urls := agentURLs(d.opts.Config)

	timeout := d.opts.MACLearnTimeout
	if timeout <= 0 {
		timeout = DefaultMACLearnTimeout
	}
	interval := macLearnPollInterval
	if interval > timeout/10 {
		interval = timeout / 10
	}
	d.opts.Log.Info("mac-learn gate: waiting", "macs", len(want), "agents", len(urls), "timeout", timeout)
	deadline := time.Now().Add(timeout)
	for {
		missing := d.unresolvedMACs(urls, want)
		if len(missing) == 0 {
			d.opts.Log.Info("mac-learn gate: ok", "macs", len(want), "agents", len(urls))
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("mac-learn gate: not resolved after %s: %s — agents have not learned the new port(s) (Kafka down and the periodic reconcile not yet run?)",
				timeout, strings.Join(missing, ", "))
		}
		select {
		case <-d.ctx.Done():
			return d.ctx.Err()
		case <-time.After(interval):
		}
	}
}

// unresolvedMACs returns a description of every (port, agent) pair the
// gate is still waiting on: the agent has not learned the MAC, a stale
// ghost from MAC reuse still resolves it to a different tenant, or the
// lookup itself failed. Lookup errors count as unresolved rather than
// aborting — the gate is a minutes-long poll against live HTTP
// endpoints, and one refused connection during an agent's busy moment
// must not kill the run; a persistent error surfaces verbatim in the
// timeout message. A Found hit with an empty TenantID passes the
// tenant check — a real agent always carries the tenant on a hit, so
// the leniency only lets tenant-agnostic test stubs through.
func (d *driver) unresolvedMACs(urls []string, want []ResourceRef) []string {
	var missing []string
	for _, p := range want {
		for _, u := range urls {
			lk, err := d.opts.Metrics.LookupMAC(d.ctx, u, p.MAC)
			switch {
			case err != nil:
				missing = append(missing, fmt.Sprintf("%s (%s) lookup on %s failed: %v", p.DSLID, p.MAC, u, err))
			case !lk.Found:
				missing = append(missing, fmt.Sprintf("%s (%s) unknown to %s", p.DSLID, p.MAC, u))
			case lk.TenantID != "" && p.ProjectID != "" && lk.TenantID != p.ProjectID:
				missing = append(missing, fmt.Sprintf("%s (%s) stale tenant %s on %s", p.DSLID, p.MAC, lk.TenantID, u))
			}
		}
	}
	return missing
}

// captureBaseline snapshots lachesis_tenant_bytes_total across all agents and
// persists it before any traffic, so assert's deltas exclude
// everything that happened before this drive.
func (d *driver) captureBaseline() error {
	snap, err := sampleAcross(d.ctx, d.opts.Metrics, d.opts.Config.Cluster.Agents)
	if err != nil {
		return fmt.Errorf("baseline scrape: %w", err)
	}
	d.opts.State.Baseline = snap.Bytes
	d.opts.State.BaselineServers = snap.Servers
	if err := d.opts.State.Save(d.opts.StatePath); err != nil {
		return err
	}
	d.opts.Log.Info("baseline captured", "series", len(snap.Bytes), "per_server", len(snap.Servers))
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

	if f.To.VMID != "" || f.To.FIPOf != "" {
		return d.runVMFlow(i, f, srcFIP)
	}
	return d.runExternalFlow(f, srcFIP)
}

// runVMFlow streams Bytes of TCP from the source VM to the target VM,
// sinking into a busybox `nc -l` started via the target's FIP. A
// VMID target dials the VM's internal IP (the asserted bytes flow
// tenant-network paths); a FIPOf target dials the VM's floating
// address instead, forcing the hairpin DNAT/SNAT path.
func (d *driver) runVMFlow(i int, f Flow, srcFIP string) error {
	dstVM := f.To.VMID
	if dstVM == "" {
		dstVM = f.To.FIPOf
	}
	dstFIP, err := d.fip(dstVM)
	if err != nil {
		return err
	}
	dstAddr := dstFIP
	if f.To.VMID != "" {
		if dstAddr, err = internalIP(d.opts.Scenario, f.To.VMID); err != nil {
			return err
		}
	}
	if err := d.waitReady(dstVM, dstFIP); err != nil {
		return err
	}

	port := flowBasePort + i
	sink := fmt.Sprintf("nohup sh -c 'nc -l -p %d > /dev/null' >/dev/null 2>&1 &", port)
	if _, err := d.opts.Exec.Run(d.ctx, dstFIP, sink); err != nil {
		return fmt.Errorf("start sink: %w", err)
	}
	d.sleepSinkDelay()

	count := mibCount(f.Bytes)
	stream := fmt.Sprintf("dd if=/dev/zero bs=1M count=%d 2>/dev/null | nc %s %d", count, dstAddr, port)
	if _, err := d.opts.Exec.Run(d.ctx, srcFIP, stream); err != nil {
		return fmt.Errorf("stream: %w", err)
	}
	d.opts.Log.Info("flow: tcp stream", "flow", i, "from", f.From, "to", dstVM, "dst", dstAddr, "port", port, "mib", count)
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
	d.opts.Log.Info("flow: ping", "from", f.From, "to", f.To.IP, "pings", count, "payload_bytes", pingPayloadBytes)
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
	d.opts.Log.Info("waiting for ssh-ready", "vm", vmID, "addr", addr, "timeout", timeout)
	ctx, cancel := context.WithTimeout(d.ctx, timeout)
	defer cancel()
	for {
		if _, err := d.opts.Exec.Run(ctx, addr, "true"); err == nil {
			d.ready[vmID] = true
			d.opts.Log.Info("vm ssh-ready", "vm", vmID, "addr", addr)
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
