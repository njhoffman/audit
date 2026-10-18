package packages

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/njhoffman/audit/internal/exec"
	"github.com/njhoffman/audit/internal/finding"
)

func updateInventory() ([]Inventory, map[string]Meta) {
	invs := []Inventory{
		{Manager: "uv", Available: true, Packages: []Package{
			{Manager: "uv", Name: "ruff", Version: "0.9.0", Source: "pypi"},
			{Manager: "uv", Name: "black", Version: "24.1", Source: "pypi"},
			{Manager: "uv", Name: "current", Version: "1.0", Source: "pypi"},
			{Manager: "uv", Name: "mine", Source: "path:/src/mine"},
			{Manager: "uv", Name: "pinned", Version: "1.0", Source: "pypi"},
			{Manager: "uv", Name: "nometa", Version: "1.0", Source: "pypi"},
		}},
		{Manager: "go", Available: true, Packages: []Package{
			{Manager: "go", Name: "staticcheck", Version: "v0.5.0", Ident: "honnef.co/go/tools", Source: "honnef.co/go/tools/cmd/staticcheck"},
			{Manager: "go", Name: "structlayout", Version: "v0.5.0", Ident: "honnef.co/go/tools", Source: "honnef.co/go/tools/cmd/structlayout"},
			{Manager: "go", Name: "dev", Version: "(devel)", Source: "example.com/dev"},
		}},
		{Manager: "gh", Available: true, Packages: []Package{
			{Manager: "gh", Name: "sha", Version: "1a2b3c4", Ident: "o/gh-sha"},
		}},
		{Manager: "cargo", Available: false},
	}
	metas := map[string]Meta{
		"uv:ruff":               {Latest: "0.9.5"},
		"uv:black":              {Latest: "25.1"},
		"uv:current":            {Latest: "1.0"},
		"uv:pinned":             {Latest: "1.1"},
		"go:honnef.co/go/tools": {Latest: "v0.6.1"},
		"gh:o/gh-sha":           {Latest: "v2.0.0"},
	}
	return invs, metas
}

func planSummary(p Plan) map[string]string {
	out := map[string]string{}
	for _, it := range p.Items {
		v := "run"
		if it.Skip != "" {
			v = it.Skip
		}
		out[it.Manager+":"+it.Name] = v
	}
	return out
}

func TestPlanUpdatesOutdated(t *testing.T) {
	invs, metas := updateInventory()
	plan := PlanUpdates(invs, metas, PlanOptions{Exclude: []Ref{ParseRef("uv:pinned")}})
	want := map[string]string{
		"uv:ruff":         "run",
		"uv:black":        "major release; pass --major to update",
		"uv:pinned":       "excluded by packages.update.exclude",
		"go:staticcheck":  "run",
		"go:structlayout": "run",
	}
	if got := planSummary(plan); !reflect.DeepEqual(got, want) {
		t.Errorf("plan = %v\nwant %v", got, want)
	}
	if plan.NotFromRegistry != 2 || len(plan.Unmatched) != 0 {
		t.Errorf("not from registry = %d, unmatched = %v", plan.NotFromRegistry, plan.Unmatched)
	}
	if got := len(plan.Runnable()); got != 3 {
		t.Errorf("runnable = %d", got)
	}
	if c := plan.Items[0].Command; strings.Join(c, " ") != "uv tool upgrade ruff" {
		t.Errorf("command = %v", c)
	}
	for _, it := range plan.Items {
		if it.Name == "structlayout" && strings.Join(it.Command, " ") != "go install honnef.co/go/tools/cmd/structlayout@latest" {
			t.Errorf("each go binary installs its own package: %v", it.Command)
		}
	}

	plan = PlanUpdates(invs, metas, PlanOptions{Major: true})
	if got := planSummary(plan)["uv:black"]; got != "run" {
		t.Errorf("--major should update black: %q", got)
	}
}

func TestPlanUpdatesNamed(t *testing.T) {
	invs, metas := updateInventory()
	refs := []Ref{ParseRef("current"), ParseRef("mine"), ParseRef("dev"), ParseRef("sha"), ParseRef("nometa"),
		ParseRef("black"), ParseRef("cargo:nothere"), ParseRef("staticcheck")}
	plan := PlanUpdates(invs, metas, PlanOptions{Refs: refs})
	want := map[string]string{
		"uv:current":     "already at the latest release",
		"uv:mine":        "installed from path:/src/mine, not a registry",
		"go:dev":         "built from a local checkout (devel)",
		"gh:sha":         "run", // named with an unparseable version: the user asked
		"uv:nometa":      "latest version unknown; run audit packages registry",
		"uv:black":       "major release; pass --major to update",
		"go:staticcheck": "run",
	}
	if got := planSummary(plan); !reflect.DeepEqual(got, want) {
		t.Errorf("plan = %v\nwant %v", got, want)
	}
	if !reflect.DeepEqual(plan.Unmatched, []string{"cargo:nothere"}) || plan.NotFromRegistry != 0 {
		t.Errorf("unmatched = %v, not from registry = %d", plan.Unmatched, plan.NotFromRegistry)
	}
}

func TestRunUpdates(t *testing.T) {
	env, fake, _ := testEnv(t)
	fake.Add([]string{"uv", "tool", "upgrade", "ok"}, exec.Result{Stdout: "Updated ok"})
	fake.Add([]string{"uv", "tool", "upgrade", "bad"}, exec.Result{Code: 2, Stderr: "resolving\nerror: no solution\n"})
	fake.Add([]string{"pnpm", "add"}, exec.Result{Code: 1, Stdout: "ERR_PNPM_FETCH_404 not found\n"})
	fake.Add([]string{"cargo"}, exec.Result{Code: exec.ExitTimeout})
	item := func(m, n string) Planned {
		p := Package{Manager: m, Name: n, Version: "1.0"}
		return Planned{Package: p, Latest: "1.1", Command: UpdateCommand(p)}
	}
	plan := Plan{Items: []Planned{
		item("uv", "ok"), item("uv", "bad"), item("pnpm", "gone"), item("cargo", "slow"),
		{Package: Package{Manager: "uv", Name: "skip", Version: "1"}, Skip: "excluded by packages.update.exclude"},
	}}
	var started, done []string
	rs := RunUpdates(ctx, env, plan, RunOptions{Timeout: time.Minute,
		OnStart: func(p Planned) { started = append(started, p.Name) },
		OnDone:  func(p Planned, _ UpdateResult) { done = append(done, p.Name) }})
	if len(rs) != 5 || len(started) != 4 || len(done) != 4 {
		t.Fatalf("results %d, started %v, done %v", len(rs), started, done)
	}
	if rs[0].Status != UpdateOK || rs[0].Command != "uv tool upgrade ok" || rs[0].From != "1.0" || rs[0].Latest != "1.1" {
		t.Errorf("ok: %+v", rs[0])
	}
	if rs[1].Status != UpdateFailed || rs[1].Code != 2 || rs[1].Reason != "exit status 2: error: no solution" ||
		rs[1].Output != "resolving\nerror: no solution" {
		t.Errorf("stderr failure: %+v", rs[1])
	}
	if rs[2].Reason != "exit status 1: ERR_PNPM_FETCH_404 not found" {
		t.Errorf("stdout is used when stderr is empty: %+v", rs[2])
	}
	if rs[3].Reason != "timed out after 1m0s" {
		t.Errorf("timeout: %+v", rs[3])
	}
	if rs[4].Status != UpdateSkipped || rs[4].Reason != "excluded by packages.update.exclude" || len(fake.Calls) != 4 {
		t.Errorf("skip: %+v, calls %v", rs[4], fake.Calls)
	}

	fake.Calls = nil
	rs = RunUpdates(ctx, env, plan, RunOptions{StopOnError: true})
	if len(fake.Calls) != 2 || rs[2].Status != UpdateSkipped || rs[2].Reason != "not run: an earlier update failed" ||
		rs[4].Reason != "excluded by packages.update.exclude" {
		t.Errorf("stop on error: calls %v, results %+v", fake.Calls, rs)
	}

	cctx, cancel := context.WithCancel(ctx)
	cancel()
	fake.Calls = nil
	rs = RunUpdates(cctx, env, plan, RunOptions{})
	if len(fake.Calls) != 0 || rs[0].Reason != "not run: interrupted" || rs[0].Status != UpdateSkipped {
		t.Errorf("cancelled: calls %v, results %+v", fake.Calls, rs)
	}
}

func TestVerify(t *testing.T) {
	rs := []UpdateResult{
		{Manager: "uv", Name: "moved", From: "1.0", Status: UpdateOK},
		{Manager: "uv", Name: "stuck", From: "1.0", Status: UpdateOK},
		{Manager: "uv", Name: "gone", From: "1.0", Status: UpdateOK},
		{Manager: "uv", Name: "failed", From: "1.0", Status: UpdateFailed, Reason: "exit status 1"},
	}
	Verify(rs, []Inventory{{Manager: "uv", Packages: []Package{
		{Manager: "uv", Name: "moved", Version: "1.1"},
		{Manager: "uv", Name: "stuck", Version: "1.0"},
		{Manager: "uv", Name: "failed", Version: "1.0"},
	}}})
	if rs[0].Status != UpdateOK || rs[0].To != "1.1" {
		t.Errorf("moved: %+v", rs[0])
	}
	if rs[1].Status != UpdateFailed || rs[1].Reason != "the command succeeded but the version is still 1.0" {
		t.Errorf("stuck: %+v", rs[1])
	}
	if rs[2].Status != UpdateFailed || rs[2].Reason != "no longer installed after the update" {
		t.Errorf("gone: %+v", rs[2])
	}
	if rs[3].Reason != "exit status 1" {
		t.Errorf("failures are left alone: %+v", rs[3])
	}
	u := Update{Items: append(rs, UpdateResult{Status: UpdateSkipped})}
	if u.Summary() != "1 updated, 3 failed, 1 skipped" {
		t.Errorf("summary = %q", u.Summary())
	}
}

func TestTailAndLastLine(t *testing.T) {
	if got := Tail("a\nb\n", 10); got != "a\nb" {
		t.Errorf("short: %q", got)
	}
	if got := Tail("first line\nsecond\nthird\n", 12); got != "...\nthird" {
		t.Errorf("cut at a line: %q", got)
	}
	if got := Tail(strings.Repeat("x", 20), 5); got != "...\nxxxxx" {
		t.Errorf("one long line: %q", got)
	}
	if got := LastLine("a\n  b  \n\n"); got != "b" {
		t.Errorf("last line: %q", got)
	}
	if got := LastLine(" \n"); got != "" {
		t.Errorf("blank: %q", got)
	}
}

func TestOutdatedNotesFailedUpdate(t *testing.T) {
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	s := registryState(now, Meta{Manager: "uv", ID: "ruff", Latest: "0.9.5"}, Meta{Manager: "pnpm", ID: "typescript", Latest: "5.9.3"})
	s.UpdateFailures = map[string]UpdateFailure{
		"uv:ruff":         {At: now, From: "0.9.0", Reason: "exit status 2: error: no solution"},
		"pnpm:typescript": {At: now, From: "5.8.0", Reason: "attempt on an older version"},
	}
	msgs := map[string]string{}
	for _, f := range finding.RunChecks(Command, s, RegistryChecks) {
		msgs[f.Subject] = f.Message
	}
	if got := msgs["uv:ruff"]; got != "0.9.0 -> 0.9.5 (patch); last update attempt failed on 2026-10-01: exit status 2: error: no solution" {
		t.Errorf("ruff message = %q", got)
	}
	if got := msgs["pnpm:typescript"]; strings.Contains(got, "failed") {
		t.Errorf("a failure on another installed version is stale: %q", got)
	}
}
