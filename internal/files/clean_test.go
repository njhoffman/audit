package files

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/njhoffman/audit/internal/packages"
)

func TestPlanClean(t *testing.T) {
	home := t.TempDir()
	mk := func(rel string) string {
		p := filepath.Join(home, rel)
		put(t, filepath.Join(p, "x"), 10, time.Time{})
		return p
	}
	nm, cache, orphan := mk("proj/node_modules"), mk(".cache/big"), mk(".local/share/gone")
	dl := filepath.Join(home, "Downloads/old.iso")
	put(t, dl, 10, time.Time{})
	a, b := filepath.Join(home, "a.mkv"), filepath.Join(home, "b.mkv")
	put(t, a, 10, time.Time{})
	put(t, b, 10, time.Time{})
	d := Data{
		Caches: []Cache{
			{Name: "uv", Path: filepath.Join(home, ".cache/uv"), Bytes: 500 * mb, Command: []string{"uv", "cache", "clean"}},
			{Name: "apt archives", Path: "/var/cache/apt/archives", Bytes: 300 * mb, Command: []string{"apt-get", "clean"}, Root: true},
			{Name: "~/.cache/big", Path: cache, Bytes: 400 * mb},
			{Name: "tiny", Path: cache, Bytes: 1},
		},
		Build:     []BuildDir{{Path: nm, Bytes: 100 * mb}, {Path: filepath.Join(home, "gone/node_modules"), Bytes: 1}},
		Orphans:   []Orphan{{Path: orphan, Bytes: 60 * mb}},
		Downloads: []File{{Path: dl, Bytes: 10}},
		Dups:      []Dup{{Bytes: 10, Paths: []string{a, b}}},
		Trash:     5 << 30, TrashPath: filepath.Join(home, ".local/share/Trash"),
	}
	o := CleanOptions{Categories: DefaultCategories, Home: home, Roots: []string{home}, CacheMinMB: 200}
	got := map[string]string{}
	for _, it := range PlanClean(d, o).Items {
		v := strings.Join(it.Command, " ")
		if it.Skip != "" {
			v = "skip: " + it.Skip
		}
		got[it.Manager+" "+strings.TrimPrefix(it.Name, home)] = v
	}
	want := map[string]string{
		"cache /.cache/uv":              "uv cache clean",
		"cache /var/cache/apt/archives": "sudo -n apt-get clean",
		"cache /.cache/big":             "rm -rf -- " + cache,
		"build /proj/node_modules":      "rm -rf -- " + nm,
		"build /gone/node_modules":      "skip: gone, or outside files.roots",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("default plan:\n%v\nwant\n%v", got, want)
	}

	o.Categories = Categories
	plan := PlanClean(d, o)
	byCat := map[string][]string{}
	for _, it := range plan.Items {
		byCat[it.Manager] = append(byCat[it.Manager], strings.Join(it.Command, " "))
	}
	if !reflect.DeepEqual(byCat[CatDuplicates], []string{"gio trash -- " + b}) || byCat[CatTrash][0] != "gio trash --empty" ||
		byCat[CatOrphaned][0] != "gio trash -- "+orphan || byCat[CatDownloads][0] != "gio trash -- "+dl {
		t.Errorf("user files go to the trash, the first duplicate stays: %v", byCat)
	}
	o.Paths = []string{filepath.Join(home, "proj")}
	if plan := PlanClean(d, o); len(plan.Items) != 1 || plan.Items[0].Name != nm {
		t.Errorf("paths limit the plan: %+v", plan.Items)
	}
	if (CleanOptions{Home: home, Roots: []string{home}}).Safe(home) || (CleanOptions{Home: home, Roots: []string{home}}).Safe("/etc") {
		t.Error("home and outside paths are never safe")
	}
}

func TestVerifyCleanAndCategories(t *testing.T) {
	dir := t.TempDir()
	still := filepath.Join(dir, "still")
	if err := os.WriteFile(still, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	rs := []packages.UpdateResult{
		{Kind: KindClean, ID: filepath.Join(dir, "gone"), Command: "rm -rf -- x", Status: packages.UpdateOK, Latest: "removed"},
		{Kind: KindClean, ID: still, Command: "gio trash -- " + still, Status: packages.UpdateOK},
		{Kind: KindClean, ID: "uv", Command: "uv cache clean", Status: packages.UpdateOK, Latest: "cleared by uv"},
	}
	VerifyClean(rs)
	if rs[0].Status != packages.UpdateOK || rs[1].Status != packages.UpdateFailed || rs[2].To != "cleared by uv" {
		t.Errorf("verify: %+v", rs)
	}
	if c, err := ParseCategories(nil); err != nil || !reflect.DeepEqual(c, DefaultCategories) {
		t.Errorf("default: %v %v", c, err)
	}
	if c, _ := ParseCategories([]string{"ALL"}); len(c) != len(Categories) {
		t.Errorf("all: %v", c)
	}
	if _, err := ParseCategories([]string{"everything"}); err == nil {
		t.Error("unknown category")
	}
}
