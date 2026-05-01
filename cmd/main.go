package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/bpf"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func ifaceName() string {
	if v := os.Getenv("TELEMETRY_IFACE"); v != "" {
		return v
	}
	return "tapb8f0adac-bc"
}

func main() {
	iface := ifaceName()

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("remove memlock: %v", err)
	}

	objs := bpf.TelemetryObjects{}
	if err := bpf.LoadTelemetryObjects(&objs, nil); err != nil {
		log.Fatalf("load BPF objects: %v", err)
	}
	defer objs.Close()

	if err := attachTC(iface, objs.TcTelemetryIn.FD(), objs.TcTelemetryOut.FD()); err != nil {
		log.Fatalf("attach TC: %v", err)
	}
	defer detachTC(iface)
	log.Printf("telemetry active on %s — run iperf3 to observe overhead", iface)

	go statsLoop(objs.TelemetryMap, 5*time.Second)
	go gcLoop(objs.TelemetryMap, 60*time.Second)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Println("shutting down")
}

// ── TC attach / detach ────────────────────────────────────────────────────

func attachTC(ifaceName string, inFD, outFD int) error {
	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return err
	}

	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}
	if err := netlink.QdiscReplace(qdisc); err != nil {
		return err
	}

	ingress := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_INGRESS,
			Handle:    1,
			Protocol:  unix.ETH_P_ALL,
		},
		Fd:           inFD,
		Name:         "tc_telemetry_in",
		DirectAction: true,
	}
	if err := netlink.FilterReplace(ingress); err != nil {
		return err
	}

	egress := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_EGRESS,
			Handle:    2,
			Protocol:  unix.ETH_P_ALL,
		},
		Fd:           outFD,
		Name:         "tc_telemetry_out",
		DirectAction: true,
	}
	return netlink.FilterReplace(egress)
}

// detachTC removes our filters from the interface on clean shutdown.
// The kernel auto-destroys filters when a program is fully dereferenced, but
// explicit removal keeps tc state clean for back-to-back test runs.
func detachTC(ifaceName string) {
	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return
	}
	for _, parent := range []uint32{netlink.HANDLE_MIN_INGRESS, netlink.HANDLE_MIN_EGRESS} {
		filters, err := netlink.FilterList(link, parent)
		if err != nil {
			continue
		}
		for _, f := range filters {
			bf, ok := f.(*netlink.BpfFilter)
			if ok && (bf.Name == "tc_telemetry_in" || bf.Name == "tc_telemetry_out") {
				netlink.FilterDel(f) //nolint:errcheck
			}
		}
	}
	log.Printf("TC filters removed from %s", ifaceName)
}

// ── Stats loop ────────────────────────────────────────────────────────────

var zoneNames = [5]string{"external", "same-tenant", "other-tenant", "infra", "miss"}

func statsLoop(m *ebpf.Map, interval time.Duration) {
	lastRaw := make(map[bpf.TelemetryFlowKey]bpf.TelemetryFlowMetrics)
	ticker := time.NewTicker(interval)
	secs := interval.Seconds()

	for range ticker.C {
		var key bpf.TelemetryFlowKey
		var perCPU []bpf.TelemetryFlowMetrics
		active := make(map[bpf.TelemetryFlowKey]bool)
		printed := 0

		iter := m.Iterate()
		for iter.Next(&key, &perCPU) {
			active[key] = true
			agg := aggregateCPUs(perCPU)

			prev := lastRaw[key]
			lastRaw[key] = agg

			deltaBytes := delta(agg.Bytes, prev.Bytes)
			if deltaBytes == 0 {
				continue
			}

			if printed == 0 {
				fmt.Printf("─── %s ─────────────────────────────────────────────────────────\n",
					time.Now().Format("15:04:05"))
				fmt.Printf("  %-17s  %-17s  %-7s  %-11s  %8s  %10s\n",
					"SRC MAC", "DST MAC", "DIR", "ZONE", "Mbps", "Pkts/int")
			}
			printed++

			mbps := float64(deltaBytes) * 8 / 1e6 / secs
			fmt.Printf("  %-17s  %-17s  %-7s  %-11s  %8.2f  %10d\n",
				macStr(key.SrcMac), macStr(key.DstMac),
				dirName(key.Direction), zoneName(key.DstZone),
				mbps, delta(agg.Packets, prev.Packets))
		}
		if err := iter.Err(); err != nil {
			log.Printf("stats iterate: %v", err)
		}

		for k := range lastRaw {
			if !active[k] {
				delete(lastRaw, k)
			}
		}
	}
}

// ── GC loop ───────────────────────────────────────────────────────────────

// gcLoop evicts flows not seen in the last `stale` window.
// Stale entries accumulate from deleted VMs — 60s matches the lingering-ghost TTL.
func gcLoop(m *ebpf.Map, stale time.Duration) {
	ticker := time.NewTicker(stale)
	threshNs := uint64(stale.Nanoseconds())

	for range ticker.C {
		nowNs := kernelMonotonicNs()

		var key bpf.TelemetryFlowKey
		var perCPU []bpf.TelemetryFlowMetrics
		var evict []bpf.TelemetryFlowKey

		iter := m.Iterate()
		for iter.Next(&key, &perCPU) {
			agg := aggregateCPUs(perCPU)
			if nowNs > agg.LastSeenNs && nowNs-agg.LastSeenNs > threshNs {
				evict = append(evict, key)
			}
		}

		for _, k := range evict {
			m.Delete(k) //nolint:errcheck
		}
		if len(evict) > 0 {
			log.Printf("GC: evicted %d stale flow(s)", len(evict))
		}
	}
}

// kernelMonotonicNs returns nanoseconds on CLOCK_MONOTONIC, matching bpf_ktime_get_ns().
func kernelMonotonicNs() uint64 {
	var ts unix.Timespec
	unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts) //nolint:errcheck
	return uint64(ts.Sec)*1e9 + uint64(ts.Nsec)
}

// ── Helpers ───────────────────────────────────────────────────────────────

func aggregateCPUs(perCPU []bpf.TelemetryFlowMetrics) bpf.TelemetryFlowMetrics {
	var total bpf.TelemetryFlowMetrics
	for _, v := range perCPU {
		total.Bytes += v.Bytes
		total.Packets += v.Packets
		if v.LastSeenNs > total.LastSeenNs {
			total.LastSeenNs = v.LastSeenNs
		}
	}
	return total
}

// delta handles both the normal case (current ≥ last) and the reboot case
// (kernel RAM cleared → counter reset to zero → current < last).
func delta(current, last uint64) uint64 {
	if current >= last {
		return current - last
	}
	return current // reboot: treat current as a fresh absolute count
}

func macStr(b [6]uint8) string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
		b[0], b[1], b[2], b[3], b[4], b[5])
}

func dirName(d uint8) string {
	if d == 0 {
		return "INGRESS"
	}
	return "EGRESS"
}

func zoneName(z uint8) string {
	if int(z) < len(zoneNames) {
		return zoneNames[z]
	}
	return fmt.Sprintf("zone%d", z)
}
