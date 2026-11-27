package core

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/njhoffman/audit/internal/packages"
	"github.com/njhoffman/audit/internal/registry"
	"github.com/njhoffman/audit/internal/run"
)

// The follow-up work of package updates and runtime migrations that needs
// the scanner's environment and stores. The commands keep the prompts,
// sudo and progress output.

// UpdatePlan plans updating d's packages from the registry cache, with
// local metadata for what the registries do not know and the update tools
// of the scan's environment. A gap of major implies o.Major.
func (s *PackagesScanner) UpdatePlan(ctx context.Context, d packages.Data, o packages.PlanOptions) (packages.Plan, error) {
	if s.Meta == nil {
		return packages.Plan{}, errors.New("plan updates: no registry cache")
	}
	metas, err := s.Meta.PackageMeta(ctx)
	if err != nil {
		return packages.Plan{}, err
	}
	now := s.Now
	if now.IsZero() {
		now = time.Now()
	}
	metas = packages.LocalMeta(d.Inventories, metas, now)
	if slices.Contains(o.Gaps, packages.GapMajor) {
		o.Major = true
	}
	o.Tools = packages.DetectUpdateTools(s.ScanEnv)
	return packages.PlanUpdates(d.Inventories, metas, o), nil
}

// RuntimeCleanupPlan plans removing stale runtime leftovers: the
// directories saved reported as runtime.stale_dirs, and python patches no
// uv tool of d uses. When the runtime cache cannot be read the plan has
// the directories only, and the error says why.
func (s *PackagesScanner) RuntimeCleanupPlan(ctx context.Context, saved *run.Run, d packages.Data) (packages.Plan, error) {
	var dirs []string
	if saved != nil {
		for _, fd := range saved.Findings {
			if fd.Check == "runtime.stale_dirs" {
				dirs = append(dirs, fd.Subject)
			}
		}
	}
	hasGio := s.ScanEnv.Which("gio") != ""
	if s.Runtimes == nil {
		return packages.CleanupPlan(dirs, hasGio, packages.RuntimeMeta{}, nil), nil
	}
	metas, err := s.Runtimes.RuntimeMeta(ctx)
	if err != nil {
		return packages.CleanupPlan(dirs, hasGio, packages.RuntimeMeta{}, nil), err
	}
	var uv *packages.Inventory
	for i := range d.Inventories {
		if d.Inventories[i].Manager == "uv" && d.Inventories[i].Available {
			uv = &d.Inventories[i]
		}
	}
	return packages.CleanupPlan(dirs, hasGio, metas[packages.RuntimePython], uv), nil
}

// InstalledPythons are the python versions installed now, asked of l (nil
// uses a registry client over the scan's environment).
func (s *PackagesScanner) InstalledPythons(ctx context.Context, l registry.RuntimeLooker, timeout time.Duration) (map[string]bool, error) {
	if l == nil {
		l = registry.NewClient(s.ScanEnv, "", timeout)
	}
	m, err := l.LookupRuntime(ctx, packages.RuntimePython)
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, in := range m.Installs {
		out[in.Version] = true
	}
	return out, nil
}

// RememberNodeMajor records the node major of after once every pnpm
// global of u moved onto it; it reports whether it did.
func (s *PackagesScanner) RememberNodeMajor(ctx context.Context, u *packages.Update, after packages.Data) (bool, error) {
	major, ok := packages.NodeMajorAfter(u, after)
	if !ok || s.Runtimes == nil {
		return false, nil
	}
	if err := s.Runtimes.SetSetting(ctx, NodeMajorSetting, major); err != nil {
		return false, err
	}
	return true, nil
}
