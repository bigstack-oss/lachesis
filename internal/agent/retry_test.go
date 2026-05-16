package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gophercloud/gophercloud/v2"
)

// tinyInitial / tinyMax keep retry tests under a few milliseconds.
// Production callers pass neutronBackoffInitial / neutronBackoffMax.
const (
	tinyInitial = 1 * time.Millisecond
	tinyMax     = 4 * time.Millisecond
)

func TestRetryWithBackoff_SuccessFirstTry(t *testing.T) {
	var calls atomic.Int32
	err := retryWithBackoff(context.Background(), tinyInitial, tinyMax, func(context.Context) error {
		calls.Add(1)
		return nil
	})
	if err != nil {
		t.Fatalf("retryWithBackoff: %v", err)
	}
	if calls.Load() != 1 {
		t.Errorf("calls = %d, want 1", calls.Load())
	}
}

func TestRetryWithBackoff_SuccessAfterRetries(t *testing.T) {
	var calls atomic.Int32
	err := retryWithBackoff(context.Background(), tinyInitial, tinyMax, func(context.Context) error {
		n := calls.Add(1)
		if n < 3 {
			return fmt.Errorf("transient #%d", n)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("retryWithBackoff: %v", err)
	}
	if calls.Load() != 3 {
		t.Errorf("calls = %d, want 3", calls.Load())
	}
}

func TestRetryWithBackoff_NonRetryableShortCircuits(t *testing.T) {
	wantErr := gophercloud.ErrUnexpectedResponseCode{Actual: 401}
	var calls atomic.Int32
	err := retryWithBackoff(context.Background(), tinyInitial, tinyMax, func(context.Context) error {
		calls.Add(1)
		return wantErr
	})
	if err == nil {
		t.Fatal("expected non-retryable error to surface")
	}
	if !errors.As(err, new(gophercloud.ErrUnexpectedResponseCode)) {
		t.Errorf("error not preserved: %v", err)
	}
	if calls.Load() != 1 {
		t.Errorf("calls = %d, want 1 (no retries for 401)", calls.Load())
	}
}

func TestRetryWithBackoff_RespectsCtxCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var calls atomic.Int32
	go func() {
		// Let the loop fail once, then cancel before the next attempt.
		for calls.Load() == 0 {
			time.Sleep(50 * time.Microsecond)
		}
		cancel()
	}()
	err := retryWithBackoff(ctx, 5*time.Millisecond, 50*time.Millisecond, func(context.Context) error {
		calls.Add(1)
		return errors.New("transient")
	})
	if err == nil {
		t.Fatal("expected ctx cancellation to surface")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
}

func TestRetryWithBackoff_BackoffCapped(t *testing.T) {
	// Drive the loop long enough to exercise the cap. Use a fail
	// counter that succeeds after 6 attempts; the delays grow as
	// 1ms → 2ms → 4ms → 4ms (capped) → 4ms → 4ms ≈ 15ms total.
	var calls atomic.Int32
	start := time.Now()
	err := retryWithBackoff(context.Background(), 1*time.Millisecond, 4*time.Millisecond, func(context.Context) error {
		n := calls.Add(1)
		if n < 6 {
			return errors.New("transient")
		}
		return nil
	})
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("retryWithBackoff: %v", err)
	}
	if calls.Load() != 6 {
		t.Errorf("calls = %d, want 6", calls.Load())
	}
	// If the cap wasn't honoured, geometric doubling would give
	// 1+2+4+8+16+32 = 63ms. With cap=4ms it's ≤ 1+2+4*4 = 19ms.
	if elapsed > 50*time.Millisecond {
		t.Errorf("elapsed = %v exceeds expected cap budget; backoff did not cap", elapsed)
	}
}

func TestIsRetryableNeutronErr(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"401 auth", gophercloud.ErrUnexpectedResponseCode{Actual: 401}, false},
		{"403 forbidden", gophercloud.ErrUnexpectedResponseCode{Actual: 403}, false},
		{"404 missing endpoint", gophercloud.ErrUnexpectedResponseCode{Actual: 404}, false},
		{"400 bad request", gophercloud.ErrUnexpectedResponseCode{Actual: 400}, false},
		{"429 rate limit", gophercloud.ErrUnexpectedResponseCode{Actual: 429}, true},
		{"500 server error", gophercloud.ErrUnexpectedResponseCode{Actual: 500}, true},
		{"502 bad gateway", gophercloud.ErrUnexpectedResponseCode{Actual: 502}, true},
		{"503 unavailable", gophercloud.ErrUnexpectedResponseCode{Actual: 503}, true},
		{"network OpError", &net.OpError{Op: "dial"}, true},
		{"plain io.EOF", io.EOF, true},
		{"plain string", errors.New("connection refused"), true},
		// Wrapped non-retryable still classifies via errors.As.
		{"wrapped 401", fmt.Errorf("auth: %w", gophercloud.ErrUnexpectedResponseCode{Actual: 401}), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isRetryableNeutronErr(tc.err); got != tc.want {
				t.Errorf("isRetryableNeutronErr(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}
