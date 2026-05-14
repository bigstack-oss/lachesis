//go:build linux

package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// clkTck is the sysconf(_SC_CLK_TCK) value: jiffies per second.
// Hard-coded to 100, which is the kernel default and what every
// glibc on every distribution we ship to reports. If we ever land
// on a kernel where CONFIG_HZ ≠ 100, this becomes a cgo call.
const clkTck = 100

// procSample is one point-in-time observation of an agent process's
// resource use.
type procSample struct {
	when    time.Time
	rssKB   uint64
	cpuJiff uint64 // user + system time in jiffies
}

// sampleProc reads /proc/<pid>/stat and /proc/<pid>/status and
// returns a snapshot.
func sampleProc(pid int) (procSample, error) {
	var s procSample
	s.when = time.Now()

	statBytes, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return s, fmt.Errorf("read stat: %w", err)
	}
	// The comm field (#2) is parenthesised and may contain spaces or
	// closing parens; LastIndex(')') is the canonical way to find the
	// end of comm. Subsequent fields are whitespace-separated.
	rp := strings.LastIndex(string(statBytes), ")")
	if rp == -1 {
		return s, fmt.Errorf("malformed /proc/%d/stat", pid)
	}
	fields := strings.Fields(string(statBytes[rp+1:]))
	// Raw stat field indexing: utime is #14, stime is #15. After the
	// closing paren, field offsets are (raw_index - 3) since we trim
	// pid + comm + state from the front.
	if len(fields) < 13 {
		return s, fmt.Errorf("/proc/%d/stat: only %d fields after comm", pid, len(fields))
	}
	utime, err := strconv.ParseUint(fields[11], 10, 64)
	if err != nil {
		return s, fmt.Errorf("parse utime: %w", err)
	}
	stime, err := strconv.ParseUint(fields[12], 10, 64)
	if err != nil {
		return s, fmt.Errorf("parse stime: %w", err)
	}
	s.cpuJiff = utime + stime

	statusFile, err := os.Open(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return s, fmt.Errorf("open status: %w", err)
	}
	defer statusFile.Close()
	scanner := bufio.NewScanner(statusFile)
	for scanner.Scan() {
		line := scanner.Text()
		rest, ok := strings.CutPrefix(line, "VmRSS:")
		if !ok {
			continue
		}
		parts := strings.Fields(rest)
		if len(parts) == 0 {
			return s, fmt.Errorf("/proc/%d/status: VmRSS line empty", pid)
		}
		rss, err := strconv.ParseUint(parts[0], 10, 64)
		if err != nil {
			return s, fmt.Errorf("parse VmRSS: %w", err)
		}
		s.rssKB = rss
		break
	}
	if err := scanner.Err(); err != nil {
		return s, fmt.Errorf("scan status: %w", err)
	}
	return s, nil
}

// cpuPercent computes the CPU usage between two samples, expressed
// as a percentage of one core. Returns 0 when the time delta is
// non-positive (concurrent or duplicate samples).
func cpuPercent(start, end procSample) float64 {
	dt := end.when.Sub(start.when).Seconds()
	if dt <= 0 {
		return 0
	}
	djiff := end.cpuJiff - start.cpuJiff
	return float64(djiff) / float64(clkTck) / dt * 100
}
