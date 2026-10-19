package cmd

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/njhoffman/audit/internal/exec"
	"github.com/njhoffman/audit/internal/packages"
)

// sudoKeepalive refreshes the sudo timestamp well inside sudo's default
// five-minute timeout.
var sudoKeepalive = time.Minute

// sudoSession authenticates sudo once, asking for the password on the
// terminal when no credentials are cached, and keeps the timestamp fresh
// until stop is called, so commands can run with sudo -n. Without a
// terminal it needs cached credentials or a NOPASSWD rule.
func (a *app) sudoSession(ctx context.Context, env *exec.Env, why string) (stop func(), err error) {
	if r := env.Run(ctx, "sudo", []string{"-n", "-v"}, exec.Options{Timeout: 15 * time.Second}); !r.OK() {
		if r.Code == exec.ExitNotFound {
			return nil, errors.New("sudo not found; it is needed for " + why)
		}
		if !a.interactive() {
			return nil, fmt.Errorf("sudo needs a password for %s and there is no terminal; run `sudo -v` first", why)
		}
		say(a.errOut, "audit needs sudo for %s.\n", why)
		if r := env.Run(ctx, "sudo", []string{"-v"}, exec.Options{Terminal: true, Timeout: 2 * time.Minute}); !r.OK() {
			return nil, fmt.Errorf("sudo -v failed (exit %d)", r.Code)
		}
	}
	kctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		t := time.NewTicker(sudoKeepalive)
		defer t.Stop()
		for {
			select {
			case <-kctx.Done():
				return
			case <-t.C:
				if r := env.Run(kctx, "sudo", []string{"-n", "-v"}, exec.Options{Timeout: 15 * time.Second}); !r.OK() && kctx.Err() == nil {
					a.log.Warn("could not refresh sudo; later commands may fail", "exit", r.Code)
				}
			}
		}
	}()
	return func() { cancel(); <-done }, nil
}

// refreshApt runs apt-get update under sudo so the plan sees current lists.
// A failure (often one unreachable repository) is reported, not fatal.
func (a *app) refreshApt(ctx context.Context, env *exec.Env, bar bool) {
	rep := a.progress(bar)
	rep.Phase("refreshing apt's package lists", 0)
	r := env.Run(ctx, "sudo", []string{"-n", "apt-get", "update"}, exec.Options{Timeout: a.cfg.Packages.Update.Timeout})
	rep.Done()
	if !r.OK() && ctx.Err() == nil {
		out := r.Stderr
		if out == "" {
			out = r.Stdout
		}
		a.log.Warn("apt-get update failed; planning from the cached lists", "exit", r.Code, "error", packages.LastLine(out))
	}
}
