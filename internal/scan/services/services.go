package services

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/njhoffman/audit/internal/scan"
)

// Options configures a services scan.
type Options struct {
	// SkipUserScope, when true, scans only the system bus.
	SkipUserScope bool

	// MaxUnits caps the number of units enriched per scope. 0 means no cap.
	// `systemctl show` is run once per unit, so on systems with thousands of
	// units this can be slow; the cap exists for that case.
	MaxUnits int

	Findings FindingOptions
}

func DefaultOptions() Options {
	return Options{
		Findings: DefaultFindingOptions(),
	}
}

// Scan enumerates services on the system (and user) bus, enriches each with
// systemctl show, and returns a scan.Result.
func Scan(ctx context.Context, opts Options) (*scan.Result, error) {
	if opts.Findings == (FindingOptions{}) {
		opts.Findings = DefaultFindingOptions()
	}
	started := time.Now()

	enriched := []EnrichedUnit{}
	scopes := []Scope{ScopeSystem}
	if !opts.SkipUserScope && userBusAvailable() {
		scopes = append(scopes, ScopeUser)
	}

	skipped := map[Scope]string{}
	for _, sc := range scopes {
		units, err := listUnits(ctx, sc)
		if err != nil {
			skipped[sc] = err.Error()
			continue
		}
		if opts.MaxUnits > 0 && len(units) > opts.MaxUnits {
			units = units[:opts.MaxUnits]
		}
		for _, u := range units {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			props, err := showUnit(ctx, sc, u.Name)
			if err != nil {
				continue
			}
			enriched = append(enriched, EnrichedUnit{Scope: sc, Unit: u, Props: props})
		}
	}

	findings := DeriveFindings(enriched, opts.Findings)

	byActive := map[string]int{}
	byScope := map[string]int{}
	failed := []string{}
	for _, u := range enriched {
		byActive[u.Active]++
		byScope[string(u.Scope)]++
		if u.Active == "failed" {
			failed = append(failed, fmt.Sprintf("%s/%s", u.Scope, u.Name))
		}
	}

	res := &scan.Result{
		Kind:       "services",
		StartedAt:  started,
		FinishedAt: time.Now(),
		Summary: map[string]any{
			"total":     len(enriched),
			"by_active": byActive,
			"by_scope":  byScope,
			"failed":    failed,
			"skipped":   skipped,
		},
		Findings: findings,
	}
	return res, nil
}

func listUnits(ctx context.Context, sc Scope) ([]Unit, error) {
	args := []string{"--no-pager", "--no-legend", "--all", "--type=service",
		"--output=json", "list-units"}
	if sc == ScopeUser {
		args = append([]string{"--user"}, args...)
	}
	out, err := runSystemctl(ctx, args...)
	if err != nil {
		return nil, err
	}
	return parseUnits(out)
}

func showUnit(ctx context.Context, sc Scope, name string) (Properties, error) {
	args := []string{"--no-pager",
		"--property=" + strings.Join(ShowProperties, ","), "show", name}
	if sc == ScopeUser {
		args = append([]string{"--user"}, args...)
	}
	out, err := runSystemctl(ctx, args...)
	if err != nil {
		return Properties{}, err
	}
	return parseShow(out), nil
}

// runSystemctl invokes systemctl with a sanitized environment so the output
// is colorless and locale-stable, regardless of the user's shell config.
func runSystemctl(ctx context.Context, args ...string) ([]byte, error) {
	path, err := exec.LookPath("systemctl")
	if err != nil {
		return nil, fmt.Errorf("systemctl not found: %w", err)
	}
	// #nosec G204 -- path is from LookPath("systemctl"); args are a fixed
	// argv shape with at most a unit name returned by systemctl itself.
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = sanitizedEnv()
	out, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return out, fmt.Errorf("systemctl %s: %w (stderr: %s)",
				strings.Join(args, " "), err, strings.TrimSpace(string(ee.Stderr)))
		}
		return nil, fmt.Errorf("systemctl %s: %w", strings.Join(args, " "), err)
	}
	return out, nil
}

// sanitizedEnv returns a minimal environment for systemctl: PATH, locale,
// NO_COLOR, plus DBUS_* and XDG_RUNTIME_DIR so --user works when a session
// bus is reachable. Stripping the rest defeats accidental color injection.
func sanitizedEnv() []string {
	env := []string{
		"PATH=" + os.Getenv("PATH"),
		"LC_ALL=C",
		"LANG=C",
		"NO_COLOR=1",
		"SYSTEMD_COLORS=0",
		"SYSTEMD_PAGER=",
		"TERM=dumb",
	}
	for _, k := range []string{"DBUS_SESSION_BUS_ADDRESS", "XDG_RUNTIME_DIR", "HOME", "USER"} {
		if v := os.Getenv(k); v != "" {
			env = append(env, k+"="+v)
		}
	}
	return env
}

func userBusAvailable() bool {
	if os.Getenv("DBUS_SESSION_BUS_ADDRESS") != "" {
		return true
	}
	if rt := os.Getenv("XDG_RUNTIME_DIR"); rt != "" {
		// #nosec G304 G703 -- read-only Stat of the well-known session bus
		// socket path; result is not opened for I/O.
		if _, err := os.Stat(filepath.Join(rt, "bus")); err == nil {
			return true
		}
	}
	return false
}
