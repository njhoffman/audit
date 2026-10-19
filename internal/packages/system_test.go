package packages

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/njhoffman/audit/internal/exec"
	"github.com/njhoffman/audit/internal/finding"
)

func TestParseAptOutput(t *testing.T) {
	got := ParseDpkgQuery("vim\t2:9.1-1\tii \nlibfoo:amd64\t1.0\tii \nold\t0.1\trc \nheld\t3.0\thi \nbad line\n")
	want := map[string]string{"vim": "2:9.1-1", "libfoo": "1.0", "held": "3.0"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("dpkg-query: %v", got)
	}
	up := ParseAptUpgradable("Listing...\nvim/noble-updates 2:9.1-2 amd64 [upgradable from: 2:9.1-1]\nnoise\n")
	if !reflect.DeepEqual(up, map[string]string{"vim": "2:9.1-2"}) {
		t.Errorf("upgradable: %v", up)
	}
}

func TestParseSnapAndFlatpak(t *testing.T) {
	es := ParseSnapList("Name  Version  Rev  Tracking  Publisher  Notes\ncore  16-2.61  17200  latest/stable  canonical**  core\n")
	if len(es) != 1 || es[0] != (SnapEntry{"core", "16-2.61", "17200"}) {
		t.Errorf("snap: %+v", es)
	}
	if es := ParseSnapList("All snaps up to date.\n"); len(es) != 0 {
		t.Errorf("up to date: %+v", es)
	}
	ps := ParseFlatpakList("org.b\t1.0\tstable\tuser\tapp/org.b/x86_64/stable\norg.a\t\tstable\tsystem\truntime/org.a/x86_64/stable\nshort\n")
	if len(ps) != 2 || ps[0].Name != "org.b" || ps[1].Location != "system" || ps[1].Ident != "runtime/org.a/x86_64/stable" {
		t.Errorf("flatpak: %+v", ps)
	}
}

func TestAptCollect(t *testing.T) {
	env, fake, _ := testEnv(t)
	fake.AddOutput("vim\t2:9.1-1\tii \nlibssl3\t3.0.1\tii \nlibz\t1.3\tii \nkernel\t6.1\thi \n", "dpkg-query")
	fake.AddOutput("vim\nkernel\n", "apt-mark", "showmanual")
	fake.AddOutput("kernel\n", "apt-mark", "showhold")
	fake.AddOutput("Listing...\nlibssl3/noble-security 3.0.2 amd64 [upgradable from: 3.0.1]\n"+
		"kernel/noble 6.2 amd64 [upgradable from: 6.1]\n", "apt", "list", "--upgradable")
	pkgs, err := Apt{}.Collect(ctx, env)
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]Package{}
	for _, p := range pkgs {
		by[p.Name] = p
	}
	if len(by) != 3 || by["vim"].Available != "" || by["libssl3"].Available != "3.0.2" || !by["kernel"].Held || by["kernel"].Available != "6.2" {
		t.Errorf("manual packages plus anything upgradable: %+v", by)
	}
	if _, ok := by["libz"]; ok {
		t.Error("an automatic, current dependency is left out")
	}
	fake2 := &exec.Fake{}
	env.Runner = fake2
	fake2.Add([]string{"dpkg-query"}, exec.Result{Code: 2, Stderr: "boom"})
	if _, err := (Apt{}).Collect(ctx, env); err == nil {
		t.Error("dpkg-query failure is an error")
	}
}

func TestSnapAndFlatpakCollect(t *testing.T) {
	env, fake, _ := testEnv(t)
	fake.AddOutput("Name Version Rev Tracking Publisher Notes\nfirefox 131.0 4955 latest/stable mozilla** -\ncore 16-2.61 17200 latest/stable canonical** core\n", "snap", "list")
	fake.AddOutput("Name Version Rev Size Publisher Notes\nfirefox 132.0 5000 1MB mozilla** -\ncore 16-2.61 17300 1MB canonical** -\n", "snap", "refresh", "--list")
	snaps, err := Snap{}.Collect(ctx, env)
	if err != nil || len(snaps) != 2 || snaps[0].Available != "132.0" || snaps[1].Available != "16-2.61 (rev 17300)" {
		t.Errorf("snaps: %+v %v", snaps, err)
	}

	fake.AddOutput("org.app\t1.0\tstable\tsystem\tapp/org.app/x86_64/stable\norg.rt\t\t23.08\tsystem\truntime/org.rt/x86_64/23.08\n"+
		"me.user\t2.0\tstable\tuser\tapp/me.user/x86_64/stable\n", "flatpak", "list")
	fake.AddOutput("app/org.app/x86_64/stable\t1.1\nruntime/org.rt/x86_64/23.08\t\n", "flatpak", "remote-ls", "--updates", "--system")
	fake.AddOutput("", "flatpak", "remote-ls", "--updates", "--user")
	fps, err := Flatpak{}.Collect(ctx, env)
	by := map[string]Package{}
	for _, p := range fps {
		by[p.Name] = p
	}
	if err != nil || by["org.app"].Available != "1.1" || by["org.rt"].Available != "newer build" || by["me.user"].Available != "" {
		t.Errorf("flatpaks: %+v %v", by, err)
	}
}

func systemInventory() []Inventory {
	return []Inventory{
		{Manager: "apt", Available: true, Packages: []Package{
			{Manager: "apt", Name: "vim", Version: "2:9.1-1", Available: "2:9.1-2", Source: "apt"},
			{Manager: "apt", Name: "libssl3", Version: "3.0.1", Available: "3.0.2", Source: "apt"},
			{Manager: "apt", Name: "kernel", Version: "6.1", Available: "6.2", Held: true, Source: "apt"},
			{Manager: "apt", Name: "curl", Version: "8.0", Source: "apt"},
		}},
		{Manager: "snap", Available: true, Packages: []Package{
			{Manager: "snap", Name: "firefox", Version: "131.0", Available: "132.0", Source: "snap"},
		}},
		{Manager: "flatpak", Available: true, Packages: []Package{
			{Manager: "flatpak", Name: "org.app", Version: "1.0", Available: "1.1", Ident: "app/org.app/x86_64/stable", Location: "system"},
			{Manager: "flatpak", Name: "me.user", Version: "2.0", Available: "2.1", Ident: "app/me.user/x86_64/stable", Location: "user"},
		}},
	}
}

func TestPlanSystemUpdates(t *testing.T) {
	invs := systemInventory()
	metas := LocalMeta(invs, map[string]Meta{"uv:ruff": {Latest: "1"}}, time.Now())
	if _, ok := metas["uv:ruff"]; !ok || !metas["apt:vim"].Local || metas["apt:curl"].Latest != "8.0" {
		t.Fatalf("local meta keeps the cache and adds system packages: %+v", metas)
	}
	plan := PlanUpdates(invs, metas, PlanOptions{Exclude: []Ref{ParseRef("apt:libssl3")}})
	want := map[string]string{
		"apt:vim":         "run",
		"apt:libssl3":     "excluded by packages.update.exclude",
		"apt:kernel":      "held with apt-mark hold",
		"snap:firefox":    "run",
		"flatpak:org.app": "run",
		"flatpak:me.user": "run",
	}
	if got := planSummary(plan); !reflect.DeepEqual(got, want) {
		t.Errorf("plan = %v\nwant %v", got, want)
	}
	cmds := map[string]string{}
	for _, it := range plan.Items {
		cmds[it.Name] = strings.Join(it.Command, " ")
	}
	if !strings.HasPrefix(cmds["vim"], "sudo -n env DEBIAN_FRONTEND=noninteractive apt-get install -y --only-upgrade") ||
		!strings.HasSuffix(cmds["vim"], "--force-confold vim") || cmds["libssl3"] == cmds["vim"] {
		t.Errorf("apt: %q / %q", cmds["vim"], cmds["libssl3"])
	}
	if cmds["firefox"] != "sudo -n snap refresh firefox" ||
		cmds["org.app"] != "sudo -n flatpak update --system -y --noninteractive app/org.app/x86_64/stable" ||
		cmds["me.user"] != "flatpak update --user -y --noninteractive app/me.user/x86_64/stable" {
		t.Errorf("commands: %v", cmds)
	}
	if !plan.NeedsRoot() {
		t.Error("apt needs root")
	}

	invs[0].Packages[1].Available = "3.0.3"
	plan = PlanUpdates(invs, LocalMeta(invs, nil, time.Now()), PlanOptions{})
	var batch []string
	for _, it := range plan.Items {
		if it.Batch == "apt" {
			batch = append(batch, strings.Join(it.Command, " "))
		}
	}
	if len(batch) != 2 || batch[0] != batch[1] || !strings.HasSuffix(batch[0], "--force-confold vim libssl3") &&
		!strings.HasSuffix(batch[0], "--force-confold libssl3 vim") {
		t.Errorf("one apt-get call for both: %v", batch)
	}
	userOnly := PlanUpdates(invs[2:], LocalMeta(invs[2:], nil, time.Now()), PlanOptions{Refs: []Ref{ParseRef("me.user")}})
	if userOnly.NeedsRoot() {
		t.Error("a user flatpak needs no root")
	}
}

func TestRunBatchOnce(t *testing.T) {
	env, fake, _ := testEnv(t)
	fake.Add([]string{"sudo", "-n", "env"}, exec.Result{Code: 100, Stderr: "E: dpkg was interrupted"})
	invs := systemInventory()[:1]
	plan := PlanUpdates(invs, LocalMeta(invs, nil, time.Now()), PlanOptions{Refs: []Ref{ParseRef("vim"), ParseRef("libssl3")}})
	var done []string
	rs := RunUpdates(ctx, env, plan, RunOptions{OnDone: func(p Planned, r UpdateResult) { done = append(done, p.Name+":"+r.Status) }})
	if len(fake.Calls) != 1 || len(rs) != 2 || rs[0].Status != UpdateFailed || rs[1].Status != UpdateFailed ||
		rs[1].Reason != "exit status 100: E: dpkg was interrupted" || len(done) != 2 {
		t.Errorf("calls %v results %+v done %v", fake.Calls, rs, done)
	}
}

func TestVerifySystem(t *testing.T) {
	rs := []UpdateResult{
		{Manager: "flatpak", Name: "org.rt", From: "1.0", Status: UpdateOK},
		{Manager: "apt", Name: "vim", From: "2:9.1-1", Status: UpdateOK},
		{Manager: "snap", Name: "firefox", From: "131.0", Status: UpdateOK},
	}
	Verify(rs, []Inventory{
		{Manager: "flatpak", Packages: []Package{{Manager: "flatpak", Name: "org.rt", Version: "1.0"}}},
		{Manager: "apt", Packages: []Package{{Manager: "apt", Name: "vim", Version: "2:9.1-1", Available: "2:9.1-2"}}},
		{Manager: "snap", Packages: []Package{{Manager: "snap", Name: "firefox", Version: "132.0"}}},
	})
	if rs[0].Status != UpdateOK || rs[0].To != "1.0" {
		t.Errorf("same version, nothing pending: %+v", rs[0])
	}
	if rs[1].Status != UpdateFailed {
		t.Errorf("still pending: %+v", rs[1])
	}
	if rs[2].Status != UpdateOK || rs[2].To != "132.0" {
		t.Errorf("snap: %+v", rs[2])
	}
}

func TestSystemChecks(t *testing.T) {
	env, _, home := testEnv(t)
	stamp := filepath.Join(home, "update-success-stamp")
	writeFile(t, stamp, "")
	now := time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC)
	if err := os.Chtimes(stamp, now.Add(-10*24*time.Hour), now.Add(-10*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	invs := systemInventory()
	s := &State{Ctx: ctx, Env: env, Inventories: invs, Meta: LocalMeta(invs, nil, now), Now: now, AptStamp: stamp}
	got := map[string][]finding.Finding{}
	for _, f := range finding.RunChecks(Command, s, append(append([]finding.Check[*State]{}, Checks...), RegistryChecks...)) {
		got[f.Check] = append(got[f.Check], f)
	}
	if fs := got["apt.stale_lists"]; len(fs) != 1 || fs[0].Severity != finding.Notice || !strings.Contains(fs[0].Message, "10 days ago") {
		t.Errorf("stale lists: %+v", fs)
	}
	if fs := got["apt.held"]; len(fs) != 1 || fs[0].Details[0] != "kernel 6.1 -> 6.2" {
		t.Errorf("held: %+v", fs)
	}
	subjects := map[string]string{}
	for _, f := range got["registry.outdated"] {
		subjects[f.Subject] = f.Message
	}
	if len(subjects) != 6 || !strings.HasPrefix(subjects["apt:vim"], "2:9.1-1 -> 2:9.1-2 (") || len(got["registry.major_behind"]) != 0 {
		t.Errorf("system packages count as outdated, never as major: %v %+v", subjects, got["registry.major_behind"])
	}
	if err := os.Chtimes(stamp, now, now); err != nil {
		t.Fatal(err)
	}
	if fs := finding.RunChecks(Command, s, []finding.Check[*State]{{ID: "apt.stale_lists", Fn: aptStaleLists}}); len(fs) != 0 {
		t.Errorf("fresh lists: %+v", fs)
	}
}
