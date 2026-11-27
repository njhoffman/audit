package cmd

import (
	"github.com/spf13/cobra"
)

// lockAction holds command's scan lock for the rest of an action c runs
// (its plan, apply and rescan), so another audit process neither scans
// the command nor runs an action on it meanwhile. The scans the action
// runs under c's context reuse the lock. Call the release when the action
// ends.
func (a *app) lockAction(c *cobra.Command, command string) (func(), error) {
	rep := a.progress(true)
	ctx, unlock, err := a.engine.Lock(c.Context(), command, rep)
	rep.Done()
	if err != nil {
		return nil, err
	}
	c.SetContext(ctx)
	return unlock, nil
}
