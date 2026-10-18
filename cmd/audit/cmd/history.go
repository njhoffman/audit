package cmd

import (
	"fmt"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/njhoffman/audit/internal/core"
	"github.com/njhoffman/audit/internal/store"
)

func newHistoryCmd(a *app) *cobra.Command {
	var (
		limit  int
		asJSON bool
	)
	c := &cobra.Command{
		Use:       "history [COMMAND]",
		Short:     "List saved runs, newest first",
		Args:      cobra.MaximumNArgs(1),
		ValidArgs: core.Commands,
		RunE: func(c *cobra.Command, args []string) error {
			command := ""
			if len(args) == 1 {
				command = args[0]
				if !slices.Contains(core.Commands, command) {
					return fmt.Errorf("unknown command %q (want %s)", command, strings.Join(core.Commands, ", "))
				}
			}
			if err := a.load(); err != nil {
				return err
			}
			h, err := a.store.History(c.Context(), command, limit)
			if err != nil {
				return err
			}
			if asJSON {
				if h == nil {
					h = []store.RunInfo{}
				}
				return a.writeJSON(h)
			}
			a.printer().History(h)
			return nil
		},
	}
	c.Flags().IntVarP(&limit, "limit", "l", 20, "show at most this many runs (0 for all)")
	c.Flags().BoolVarP(&asJSON, "json", "j", false, "print runs as JSON")
	return c
}
