package agent

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/gophercloud/gophercloud/v2"
)

// retryWithBackoff invokes fetch repeatedly with exponential backoff
// (`initial`, doubling, capped at `max`) until it returns nil or
// ctx is cancelled. Errors classified as non-retryable by
// [isRetryableNeutronErr] short-circuit the loop and propagate
// immediately — they indicate a configuration problem (bad
// credentials, wrong endpoint) that won't fix itself.
//
// `initial` and `max` are arguments rather than constants so unit
// tests can drive the loop with sub-millisecond delays. Production
// callers pass [neutronBackoffInitial] / [neutronBackoffMax].
func retryWithBackoff(
	ctx context.Context,
	initial, max time.Duration,
	fetch func(context.Context) error,
) error {
	delay := initial
	attempt := 1
	for {
		err := fetch(ctx)
		if err == nil {
			if attempt > 1 {
				slog.Info("neutron reachable after retries",
					"component", componentNeutron,
					"attempts", attempt)
			}
			return nil
		}
		if !isRetryableNeutronErr(err) {
			return err
		}
		slog.Warn("neutron unreachable; backing off",
			"component", componentNeutron,
			"attempt", attempt,
			"next_in", delay,
			"err", err,
		)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
		delay *= 2
		if delay > max {
			delay = max
		}
		attempt++
	}
}

// isRetryableNeutronErr decides whether a fetch failure is worth
// retrying. The boundary lines up with the operator's mental model:
// transient (network, 5xx, 429) retries; permanent (auth, 4xx)
// doesn't. A persistently-retried 401 would burn cycles forever
// without surfacing the real problem.
func isRetryableNeutronErr(err error) bool {
	if err == nil {
		return false
	}
	var codeErr gophercloud.ErrUnexpectedResponseCode
	if errors.As(err, &codeErr) {
		// 5xx — server-side trouble, retry. 429 — rate-limited,
		// retry after backoff. Everything else (auth, not-found,
		// bad request) is the operator's problem.
		if codeErr.Actual >= 500 || codeErr.Actual == 429 {
			return true
		}
		return false
	}
	// Network / DNS / TLS / parse errors all surface as untyped
	// errors here. They are typically transient — retry.
	return true
}
