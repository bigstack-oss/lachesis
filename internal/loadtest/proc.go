//go:build linux

package loadtest

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/bigstack-oss/lachesis/internal/metrics"
)

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

// sampleWindow polls the agent's /proc every interval until ctx is
// cancelled, then returns the peak VmRSS (kB) and average CPU% over
// the whole window. start is the pre-load baseline used to compute
// the integrated CPU%.
func sampleWindow(pid int, ctx context.Context, interval time.Duration, start procSample) (uint64, float64) {
	var (
		rssPeak uint64
		prev    = start
		last    = start
	)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			final, err := sampleProc(pid)
			if err == nil {
				if final.rssKB > rssPeak {
					rssPeak = final.rssKB
				}
				last = final
			}
			return rssPeak, cpuPercent(start, last)
		case <-t.C:
			s, err := sampleProc(pid)
			if err != nil {
				// Process may have exited; surface to caller via stderr.
				fmt.Fprintf(os.Stderr, "loadtest: sample failed: %v\n", err)
				return rssPeak, cpuPercent(start, prev)
			}
			if s.rssKB > rssPeak {
				rssPeak = s.rssKB
			}
			prev = s
			last = s
		}
	}
}

// sumBytesTotal fetches /metrics once and returns the sum of every
// lachesis_bytes_total sample. Used as a liveness check that the BPF
// program actually saw the load-generated traffic.
func sumBytesTotal(httpAddr string) (uint64, error) {
	resp, err := http.Get("http://" + httpAddr + "/metrics")
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, err
	}
	re := regexp.MustCompile(regexp.QuoteMeta(metrics.MetricBytesTotal) + `\{[^}]*\} (\d+(?:\.\d+e\+?\d+)?)`)
	var total uint64
	for _, m := range re.FindAllStringSubmatch(string(b), -1) {
		f, err := strconv.ParseFloat(m[1], 64)
		if err != nil {
			continue
		}
		total += uint64(f)
	}
	return total, nil
}
