package packages

import "testing"

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		manager, a, b string
		want          int
	}{
		{"uv", "1.2.3", "1.2.3", 0},
		{"uv", "1.2", "1.2.0", 0},
		{"uv", "1.10.0", "1.9.9", 1},
		{"uv", "0.9.0", "1.0.0", -1},
		{"uv", "2.0.0rc1", "2.0.0", -1},
		{"uv", "2.0.0a1", "2.0.0b1", -1},
		{"uv", "2.0.0b2", "2.0.0rc1", -1},
		{"uv", "2.0.0.dev3", "2.0.0a1", -1},
		{"uv", "2.0.0.post1", "2.0.0", 1},
		{"uv", "24.10.0", "24.8.0", 1},
		{"pnpm", "5.0.0-beta.3", "5.0.0-beta.10", -1},
		{"pnpm", "5.0.0-beta.3", "5.0.0", -1},
		{"pnpm", "v1.0.0", "1.0.0", 0},
		{"pnpm", "1.0.0+build.5", "1.0.0", 0},
		{"pnpm", "1.0.0-nightly", "1.0.0", -1},
		{"gem", "3.2.0.pre", "3.2.0", -1},
		{"gem", "1.16.3", "1.16.10", -1},
		{"cargo", "0.24.1", "0.24.0", 1},
		{"go", "v0.21.0", "v0.22.0", -1},
		{"go", "v1.2.3", "v1.2.3-rc.1", 1},
		{"go", "v0.0.0-20240101000000-abcdefabcdef", "v0.1.0", -1},
		{"uv", "20240101", "20231231", 1},
	}
	for _, c := range cases {
		got, ok := CompareVersions(c.manager, c.a, c.b)
		if !ok || got != c.want {
			t.Errorf("CompareVersions(%s, %q, %q) = %d, %v; want %d", c.manager, c.a, c.b, got, ok, c.want)
		}
		if back, _ := CompareVersions(c.manager, c.b, c.a); back != -c.want {
			t.Errorf("CompareVersions(%s, %q, %q) = %d; not antisymmetric", c.manager, c.b, c.a, back)
		}
	}
}

func TestCompareVersionsUnparseable(t *testing.T) {
	for _, c := range [][3]string{
		{"gh", "a1b2c3d", "v1.0.0"},
		{"go", "(devel)", "v1.0.0"},
		{"uv", "", "1.0"},
		{"gh", "1a2b3c4", "v1.0.0"},
	} {
		if _, ok := CompareVersions(c[0], c[1], c[2]); ok {
			t.Errorf("CompareVersions(%q, %q, %q) should not parse", c[0], c[1], c[2])
		}
	}
}

func TestVersionGap(t *testing.T) {
	cases := []struct {
		manager, installed, latest string
		want                       Gap
	}{
		{"uv", "1.2.3", "1.2.3", GapCurrent},
		{"uv", "1.2.3", "1.2.4", GapPatch},
		{"uv", "1.2.3", "1.3.0", GapMinor},
		{"uv", "1.2.3", "2.0.0", GapMajor},
		{"uv", "2.0.0rc1", "2.0.0", GapPatch},
		{"uv", "2.1.0", "2.0.0", GapAhead},
		{"pnpm", "5.9.0", "10.18.2", GapMajor},
		{"go", "v0.21.0", "v0.22.0", GapMinor},
		{"go", "v1.4.0", "v2.0.0", GapMajor},
		{"gh", "abc1234", "v1.0.0", GapUnknown},
	}
	for _, c := range cases {
		if got := VersionGap(c.manager, c.installed, c.latest); got != c.want {
			t.Errorf("VersionGap(%s, %q, %q) = %q want %q", c.manager, c.installed, c.latest, got, c.want)
		}
	}
	if GapCurrent.Behind() || GapAhead.Behind() || GapUnknown.Behind() || !GapMajor.Behind() {
		t.Error("Behind wrong")
	}
}

func TestIsPrerelease(t *testing.T) {
	for v, want := range map[string]bool{"1.0.0": false, "1.0.0-rc.1": true, "2.0b1": true, "1.0.post1": false, "x": false} {
		if IsPrerelease(v) != want {
			t.Errorf("IsPrerelease(%q) != %v", v, want)
		}
	}
}
