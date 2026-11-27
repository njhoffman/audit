package core

import (
	"context"
	"errors"
	"testing"

	"github.com/njhoffman/audit/internal/exec"
	"github.com/njhoffman/audit/internal/finding"
	"github.com/njhoffman/audit/internal/packages"
	"github.com/njhoffman/audit/internal/run"
)

func TestUpdatePlan(t *testing.T) {
	ctx := context.Background()
	d := packages.Data{Inventories: []packages.Inventory{{Manager: "uv", Available: true,
		Packages: []packages.Package{{Manager: "uv", Name: "ruff", Version: "1.2.0", Source: "pypi"}}}}}
	meta := &memMeta{m: map[string]packages.Meta{packages.MetaKey("uv", "ruff"): {Manager: "uv", ID: "ruff", Latest: "2.0.0"}}}
	s := &PackagesScanner{Meta: meta, ScanEnv: &exec.Env{}}
	plan, err := s.UpdatePlan(ctx, d, packages.PlanOptions{})
	if err != nil || len(plan.Items) != 1 || plan.Items[0].Skip == "" {
		t.Fatalf("a major release waits for --major: %v %+v", err, plan.Items)
	}
	plan, err = s.UpdatePlan(ctx, d, packages.PlanOptions{Gaps: []packages.Gap{packages.GapMajor}})
	if err != nil || len(plan.Runnable()) != 1 {
		t.Errorf("--gap major implies --major: %v %+v", err, plan.Items)
	}
	if _, err := (&PackagesScanner{}).UpdatePlan(ctx, d, packages.PlanOptions{}); err == nil {
		t.Error("no registry cache is an error")
	}
}

func TestRuntimeCleanupPlan(t *testing.T) {
	ctx := context.Background()
	saved := &run.Run{Findings: []finding.Finding{
		{Check: "runtime.stale_dirs", Subject: "/old/node"}, {Check: "runtime.other", Subject: "/kept"}}}
	s := &PackagesScanner{ScanEnv: &exec.Env{}}
	plan, err := s.RuntimeCleanupPlan(ctx, saved, packages.Data{})
	if err != nil || len(plan.Items) != 1 || plan.Items[0].Name != "/old/node" || plan.Items[0].Skip == "" {
		t.Errorf("stale dirs only, skipped without gio: %v %+v", err, plan.Items)
	}
	s.Runtimes = &memRuntimes{err: errors.New("locked")}
	if plan, err = s.RuntimeCleanupPlan(ctx, saved, packages.Data{}); err == nil || len(plan.Items) != 1 {
		t.Errorf("an unreadable cache still plans the dirs: %v %+v", err, plan.Items)
	}
	if plan, _ = s.RuntimeCleanupPlan(ctx, nil, packages.Data{}); len(plan.Items) != 0 {
		t.Errorf("no saved run: %+v", plan.Items)
	}
}

func TestInstalledPythons(t *testing.T) {
	ctx := context.Background()
	s := &PackagesScanner{ScanEnv: &exec.Env{}}
	l := runtimeTable{packages.RuntimePython: {Name: packages.RuntimePython,
		Installs: []packages.PythonInstall{{Version: "3.13.1"}, {Version: "3.14.0"}}}}
	got, err := s.InstalledPythons(ctx, l, 0)
	if err != nil || !got["3.13.1"] || !got["3.14.0"] || len(got) != 2 {
		t.Errorf("pythons %v %v", got, err)
	}
	if _, err := s.InstalledPythons(ctx, runtimeTable{}, 0); err == nil {
		t.Error("a failed lookup is an error")
	}
}

func TestRememberNodeMajor(t *testing.T) {
	ctx := context.Background()
	u := &packages.Update{Items: []packages.UpdateResult{
		{Kind: packages.KindMigration, Manager: "pnpm", Name: "eslint", Status: packages.UpdateOK}}}
	after := packages.Data{Runtimes: []packages.RuntimeStatus{{Name: "node", Version: "26.1.0"}}}
	if ok, err := (&PackagesScanner{}).RememberNodeMajor(ctx, u, after); ok || err != nil {
		t.Errorf("no store, nothing remembered: %v %v", ok, err)
	}
	rts := &memRuntimes{settings: map[string]string{}}
	if ok, err := (&PackagesScanner{Runtimes: rts}).RememberNodeMajor(ctx, u, after); !ok || err != nil || rts.settings[NodeMajorSetting] != "26" {
		t.Errorf("remembered: %v %v %v", ok, err, rts.settings)
	}
}
