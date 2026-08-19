// Command scenariotest realizes a declared topology, drives traffic
// across it, and asserts the agent's /metrics deltas match. Tier 4 of
// the test pyramid.
//
// Run `scenariotest help` for the command reference.
//
// docs/development/testing.md
package main

import (
	"errors"
	"fmt"
	"os"
)

// usageError marks a bad invocation (missing/unknown flags, args,
// subcommands). main exits 2 for these, 1 for runtime failures.
type usageError struct{ err error }

func (u usageError) Error() string {
	if u.err == nil {
		return ""
	}
	return u.err.Error()
}

// errFailed marks a command whose report was emitted but not OK:
// exit 1 with no extra stderr line (the report already said why).
var errFailed = errors.New("report not ok")

func main() {
	err := newRoot().Execute()
	if err == nil {
		return
	}
	var uerr usageError
	switch {
	case errors.As(err, &uerr):
		if uerr.err != nil {
			fmt.Fprintf(os.Stderr, "%s\nRun 'scenariotest --help' for usage.\n", uerr)
		}
		os.Exit(2)
	case errors.Is(err, errFailed):
		os.Exit(1)
	default:
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
