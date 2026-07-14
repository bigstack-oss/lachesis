//go:build linux

package loadtest

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	tns "github.com/bigstack-oss/lachesis/internal/testenv/netns"
)

// driveLoad runs cfg.Workers concurrent TCP workers for cfg.Duration
// while sampling /proc/<agent>/{stat,status} once per second, then
// scrapes /metrics once for the bytes-observed liveness number.
func driveLoad(cfg Config, e *env) (Result, error) {
	first, err := sampleProc(e.agent.Process.Pid)
	if err != nil {
		return Result{}, fmt.Errorf("initial sample: %w", err)
	}

	loadCtx, cancel := context.WithTimeout(context.Background(), cfg.Duration)
	defer cancel()

	var wg sync.WaitGroup
	for i := 0; i < cfg.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := sustainedTCPSend(loadCtx, e.ns, e.outerIP, e.sinkPort); err != nil && loadCtx.Err() == nil {
				fmt.Fprintf(os.Stderr, "loadtest: worker exited: %v\n", err)
			}
		}()
	}

	rssPeakKB, cpuAvgPct := sampleWindow(e.agent.Process.Pid, loadCtx, time.Second, first)
	wg.Wait()

	bytesObs, err := sumBytesTotal(cfg.HTTPAddr)
	if err != nil {
		return Result{}, fmt.Errorf("read final /metrics: %w", err)
	}
	return Result{RSSPeakKB: rssPeakKB, CPUAvgPct: cpuAvgPct, BytesObs: bytesObs}, nil
}

// sustainedTCPSend opens one long-lived TCP connection from inside ns
// and writes [workerChunkSize] chunks back-to-back until ctx is
// cancelled. Using a single connection per worker (vs. dial-write-
// close per iteration) avoids ephemeral-port exhaustion during a long
// load window — the kernel's TIME_WAIT pool fills up in seconds at
// our rate otherwise.
func sustainedTCPSend(ctx context.Context, src *tns.NS, dstIP net.IP, dstPort uint16) error {
	dst := net.JoinHostPort(dstIP.String(), strconv.Itoa(int(dstPort)))
	return src.Do(func() error {
		d := &net.Dialer{Timeout: workerDialTimeout}
		conn, err := d.DialContext(ctx, "tcp", dst)
		if err != nil {
			return fmt.Errorf("loadtest: dial %s: %w", dst, err)
		}
		defer conn.Close()
		buf := make([]byte, workerChunkSize)
		for ctx.Err() == nil {
			if _, err := conn.Write(buf); err != nil {
				// Sink shutdown is the expected end-of-window path.
				if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
					return nil
				}
				return fmt.Errorf("loadtest: write: %w", err)
			}
		}
		return nil
	})
}

// serveSink starts a discarding TCP listener. Returns the bound
// address and a stop function that closes the listener and any
// in-flight connections.
//
// This deliberately duplicates testenv/traffic.ServeTCPSink rather
// than importing it: that helper takes a *testing.T and so links the
// testing package, which would pull test-only flags into the loadtest
// CLI binary. The shared logic is a few lines of accept-and-discard;
// keep the two in sync.
func serveSink() (net.Addr, func()) {
	ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		panic(fmt.Errorf("loadtest: listen: %w", err))
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(io.Discard, conn)
			}(c)
		}
	}()
	return ln.Addr(), func() { _ = ln.Close() }
}
