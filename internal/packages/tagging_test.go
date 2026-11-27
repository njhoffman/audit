package packages

import (
	"strings"
	"testing"
	"time"
)

func TestTagCandidates(t *testing.T) {
	tagged := &Meta{TaggedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	pk := func(name string) Package { return Package{Manager: "uv", Name: name} }
	as := []Annotated{{Inventory: Inventory{Manager: "uv", Packages: []Package{pk("a"), pk("b"), pk("c")}},
		Items: []Item{{Package: pk("a"), Meta: &Meta{}}, {Package: pk("b"), Meta: tagged}, {Package: pk("c")}, {Package: pk("a"), Meta: &Meta{}}}}}
	names := func(items []Item) string {
		var out []string
		for _, it := range items {
			out = append(out, it.Name)
		}
		return strings.Join(out, ",")
	}
	for _, tc := range []struct {
		refs  []Ref
		retag bool
		want  string
	}{
		{nil, false, "a"},
		{nil, true, "a,b"},
		{[]Ref{ParseRef("b")}, true, "b"},
		{[]Ref{ParseRef("b")}, false, ""},
	} {
		if got := names(TagCandidates(as, tc.refs, tc.retag)); got != tc.want {
			t.Errorf("refs %v retag %v: %q, want %q", tc.refs, tc.retag, got, tc.want)
		}
	}
}
