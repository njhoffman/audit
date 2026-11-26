package packages

import (
	"testing"
)

func programInventories() []Annotated {
	return []Annotated{
		{Inventory: Inventory{Manager: "apt", Available: true}, Items: []Item{
			{Package: Package{Manager: "apt", Name: "openssh-server", Version: "1:9.6p1-3ubuntu13"}}}},
		{Inventory: Inventory{Manager: "snap", Available: true}, Items: []Item{
			{Package: Package{Manager: "snap", Name: "docker", Version: "27.2.0"}}}},
		{Inventory: Inventory{Manager: "bins", Available: true}, Items: []Item{
			{Package: Package{Manager: "bins", Name: "sshd", Version: "9.8p1", Location: "/home/u/bin/sshd"}}}},
		{Inventory: Inventory{Manager: "cargo", Available: true, BinDirs: []string{"/home/u/.cargo/bin"}}, Items: []Item{
			{Package: Package{Manager: "cargo", Name: "ripgrep", Version: "14.1.0", Executables: []string{"rg"}}}}},
	}
}

func TestOwnerOf(t *testing.T) {
	as := programInventories()
	dpkg := func(p string) string {
		if p == "/usr/sbin/sshd" {
			return "openssh-server:amd64"
		}
		return ""
	}
	for _, tc := range []struct {
		path, manager, name string
	}{
		{"/usr/sbin/sshd", "apt", "openssh-server"},
		{"/snap/bin/docker.compose", "snap", "docker"},
		{"/home/u/bin/sshd", "bins", "sshd"},
		{"/home/u/.cargo/bin/rg", "cargo", "ripgrep"},
		{"/home/u/.cargo/bin/other", "cargo", ""},
		{"/opt/x/bin/sshd", "", ""},
	} {
		m, it := OwnerOf(tc.path, as, dpkg)
		name := ""
		if it != nil {
			name = it.Name
		}
		if m != tc.manager || name != tc.name {
			t.Errorf("%s: %q %q, want %q %q", tc.path, m, name, tc.manager, tc.name)
		}
	}
	if m, _ := OwnerOf("/usr/sbin/sshd", as[1:], dpkg); m != "" {
		t.Errorf("without an apt inventory dpkg is not asked: %q", m)
	}
}

func TestResolveProgramAndNewerShadowed(t *testing.T) {
	as := programInventories()
	dpkg := func(p string) string {
		if p == "/usr/sbin/sshd" {
			return "openssh-server"
		}
		return ""
	}
	which := func(name string) []string {
		if name == "sshd" {
			return []string{"/usr/sbin/sshd", "/sbin/sshd", "/home/u/bin/sshd"}
		}
		return nil
	}
	// /sbin is a link to /usr/sbin, so its sshd is the same file.
	resolve := func(p string) string {
		if p == "/sbin/sshd" {
			return "/usr/sbin/sshd"
		}
		return p
	}
	pp := ResolveProgram("sshd", []string{"sshd", "missing"}, which, resolve, func(p string) (string, *Item) { return OwnerOf(p, as, dpkg) })
	if len(pp.Copies) != 2 || pp.Copies[0].Manager != "apt" || pp.Copies[1].Manager != "bins" || len(pp.Shadowed()) != 1 {
		t.Fatalf("copies %+v", pp.Copies)
	}
	if c := pp.NewerShadowed(); c == nil || c.Path != "/home/u/bin/sshd" {
		t.Errorf("9.8p1 shadowed by 1:9.6p1-3ubuntu13 is newer: %+v", c)
	}
	pp.Copies[0], pp.Copies[1] = pp.Copies[1], pp.Copies[0]
	if c := pp.NewerShadowed(); c != nil {
		t.Errorf("an older shadowed copy is not flagged: %+v", c)
	}
	if c := (ProgramPackages{Copies: []ProgramCopy{{Path: "/x"}}}).NewerShadowed(); c != nil {
		t.Errorf("an unowned copy that runs compares with nothing: %+v", c)
	}
	for in, want := range map[string]string{"1:9.6p1-3ubuntu13": "9.6p1", "v1.2.3": "1.2.3", "3.0pl1-196ubuntu2": "3.0pl1", "27.2.0": "27.2.0"} {
		if got := UpstreamVersion(in); got != want {
			t.Errorf("UpstreamVersion(%q) = %q, want %q", in, got, want)
		}
	}
}
