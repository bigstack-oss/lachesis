package main

import (
	"fmt"
	"io"
	"os"
	"text/tabwriter"

	"github.com/bigstack-oss/lachesis/cmd/scenariotest/scenarios"
	"github.com/bigstack-oss/lachesis/internal/scenariotest"
	"github.com/spf13/cobra"
)

func newListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "Show registered scenarios.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runList(os.Stdout)
		},
	}
}

func runList(out io.Writer) error {
	all := scenarios.All()
	if len(all) == 0 {
		fmt.Fprintln(out, "(no scenarios registered)")
		return nil
	}
	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tFLOWS\tEXPECT\tSTEPS\tPLACEMENT\tDESC")
	for _, s := range all {
		placement := "(scheduler)"
		if len(s.Placement) > 0 {
			placement = fmt.Sprintf("%d pinned", len(s.Placement))
		}
		flows, expects := countDeclared(s)
		fmt.Fprintf(tw, "%s\t%d\t%d\t%d\t%s\t%s\n", s.Name, flows, expects, len(s.Steps), placement, s.Desc)
	}
	tw.Flush()
	return nil
}

// countDeclared totals a scenario's flows and expectations wherever
// they are declared — top-level for plain scenarios, inside Drive and
// Assert steps for scripted ones.
func countDeclared(s *scenariotest.Scenario) (flows, expects int) {
	flows, expects = len(s.Flows), len(s.Expect)
	for _, st := range s.Steps {
		switch st := st.(type) {
		case scenariotest.DriveStep:
			flows += len(st.Flows)
		case scenariotest.AssertStep:
			expects += len(st.Expect)
		}
	}
	return flows, expects
}
