//go:build linux

// Package traffic generates network traffic for testenv-based tests.
//
// It uses real TCP via net.Dial inside the source netns; the receiver is a
// minimal listener in the caller's current netns. AF_PACKET / gopacket
// injection is intentionally not provided here; add it only when a specific
// scenario needs spoofed headers (e.g., port-security tests).
package traffic

import (
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	tns "github.com/bigstack-oss/cube-cos-network-telemetry/internal/testenv/netns"
)

// SendTCPStream opens a TCP connection from inside src to dstIP:dstPort and
// writes payloadBytes zero bytes, then closes. Returns when the write
// completes or the dial/write fails.
func SendTCPStream(src *tns.NS, dstIP net.IP, dstPort uint16, payloadBytes int) error {
	dst := net.JoinHostPort(dstIP.String(), strconv.Itoa(int(dstPort)))
	dialer := &net.Dialer{Timeout: 5 * time.Second}

	return src.Do(func() error {
		conn, err := dialer.Dial("tcp", dst)
		if err != nil {
			return fmt.Errorf("traffic: dial %s: %w", dst, err)
		}
		defer conn.Close()

		buf := make([]byte, 8192)
		for remaining := payloadBytes; remaining > 0; {
			n := min(len(buf), remaining)
			w, err := conn.Write(buf[:n])
			if err != nil {
				return fmt.Errorf("traffic: write: %w", err)
			}
			remaining -= w
		}
		return nil
	})
}

// ServeTCPSink starts a TCP listener that accepts connections, drains
// incoming bytes to io.Discard, and stops when the returned stop fn is called.
// Listens on 0.0.0.0:0 in the caller's current netns.
func ServeTCPSink(t *testing.T) (net.Addr, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("traffic: listen: %v", err)
	}

	var wg sync.WaitGroup
	wg.Go(func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Go(func() {
				defer c.Close()
				_, _ = io.Copy(io.Discard, c)
			})
		}
	})

	stop := func() {
		_ = ln.Close()
		wg.Wait()
	}
	return ln.Addr(), stop
}
