package store

import (
	"reflect"
	"testing"
	"time"

	"github.com/njhoffman/audit/internal/packages"
)

func TestPackageMetaRoundTrip(t *testing.T) {
	s := open(t)
	at := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	m := packages.Meta{
		Manager: "pnpm", ID: "typescript", Registry: packages.RegistryNpm, Latest: "5.9.3", LatestAt: at,
		Installed: "5.9.0", InstalledYanked: true, Deprecated: "use x", Archived: true, Description: "TS",
		Repo: "https://github.com/microsoft/TypeScript", Homepage: "https://typescriptlang.org", License: "Apache-2.0",
		Keywords: []string{"typescript", "compiler"}, CheckedAt: at, DescribedAt: at.Add(-time.Hour), Error: "boom",
	}
	bare := packages.Meta{Manager: "uv", ID: "ruff", Latest: "0.9.0", CheckedAt: at}
	if err := s.SavePackageMeta(ctx, []packages.Meta{m, bare}); err != nil {
		t.Fatal(err)
	}
	got, err := s.PackageMeta(ctx)
	if err != nil {
		t.Fatal(err)
	}
	g := got["pnpm:typescript"]
	g.LatestAt, g.CheckedAt, g.DescribedAt = g.LatestAt.UTC(), g.CheckedAt.UTC(), g.DescribedAt.UTC()
	if !reflect.DeepEqual(g, m) {
		t.Errorf("round trip:\n got %+v\nwant %+v", g, m)
	}
	if r := got["uv:ruff"]; r.Keywords != nil || !r.TaggedAt.IsZero() || !r.LatestAt.IsZero() {
		t.Errorf("empty fields should stay empty: %+v", r)
	}

	m.Latest, m.Error = "6.0.0", ""
	if err := s.SavePackageMeta(ctx, []packages.Meta{m}); err != nil {
		t.Fatal(err)
	}
	got, _ = s.PackageMeta(ctx)
	if len(got) != 2 || got["pnpm:typescript"].Latest != "6.0.0" || got["pnpm:typescript"].Error != "" {
		t.Errorf("save should replace: %+v", got)
	}
}

func TestPackageTags(t *testing.T) {
	s := open(t)
	err := s.AddPackageTags(ctx, []packages.Tag{
		{Manager: "pnpm", ID: "typescript", Tag: "lsp", Source: packages.TagUser},
		{Manager: "pnpm", ID: "typescript", Tag: "devtools", Source: packages.TagAI},
		{Manager: "uv", ID: "ruff", Tag: "lint", Source: packages.TagAI},
	})
	if err != nil {
		t.Fatal(err)
	}
	// Re-adding a user tag as AI keeps it a user tag.
	if err := s.ReplaceAITags(ctx, "pnpm", "typescript", []string{"lsp", "language"}); err != nil {
		t.Fatal(err)
	}
	tags, err := s.PackageTags(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := []packages.Tag{
		{Manager: "pnpm", ID: "typescript", Tag: "language", Source: packages.TagAI},
		{Manager: "pnpm", ID: "typescript", Tag: "lsp", Source: packages.TagUser},
		{Manager: "uv", ID: "ruff", Tag: "lint", Source: packages.TagAI},
	}
	if !reflect.DeepEqual(tags, want) {
		t.Errorf("tags:\n got %+v\nwant %+v", tags, want)
	}
	if by := TagsByKey(tags); !reflect.DeepEqual(by["pnpm:typescript"], []string{"language", "lsp"}) {
		t.Errorf("by key: %v", by)
	}
	n, err := s.RemovePackageTags(ctx, "pnpm", "typescript", []string{"lsp", "absent"})
	if err != nil || n != 1 {
		t.Errorf("remove: %d %v", n, err)
	}
	if tags, _ := s.PackageTags(ctx); len(tags) != 2 {
		t.Errorf("after remove: %+v", tags)
	}
}

func TestSettings(t *testing.T) {
	s := open(t)
	if v, err := s.Setting(ctx, "github_user"); v != "" || err != nil {
		t.Errorf("unset: %q %v", v, err)
	}
	for _, v := range []string{"a", "b"} {
		if err := s.SetSetting(ctx, "github_user", v); err != nil {
			t.Fatal(err)
		}
	}
	if v, _ := s.Setting(ctx, "github_user"); v != "b" {
		t.Errorf("got %q", v)
	}
}
