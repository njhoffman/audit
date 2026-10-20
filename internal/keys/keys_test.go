package keys

import (
	"strings"
	"testing"
)

func TestDefaultsValidate(t *testing.T) {
	if err := Validate(Defaults()); err != nil {
		t.Fatal(err)
	}
	d := Defaults()
	d[Quit][0] = "changed"
	if Defaults()[Quit][0] != "q" {
		t.Error("Defaults must return a copy")
	}
}

func TestValidate(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit Map
		want string
	}{
		{"unknown action", Map{"qiut": {"x"}}, `unknown action "qiut"`},
		{"empty key", Map{Quit: {""}}, "quit: empty key"},
		{"reserved", Map{Rescan: {Reserved}}, "always quits"},
		{"same screen", Map{Quit: {"d"}}, `"d" is bound to both quit and status_done on the tasks screen`},
		{"twice in one action is fine", Map{Quit: {"q", "q"}}, ""},
		{"disjoint screens share", Map{Rescan: {"x"}, Reask: {"x"}}, ""},
		{"unbound", Map{Editor: {}}, ""},
		{"rebinding frees the old key", Map{StatusDone: {"x"}, Quit: {"q", "d"}}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := Defaults()
			for k, v := range tc.edit {
				m[k] = v
			}
			err := Validate(m)
			switch {
			case tc.want == "" && err != nil:
				t.Errorf("unexpected error: %v", err)
			case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
				t.Errorf("error %v, want %q", err, tc.want)
			}
		})
	}
}

func TestFirstAndLabel(t *testing.T) {
	m := Map{PageDown: {" ", "f"}, Bottom: {"pgdown"}, Editor: {}}
	if m.First(PageDown) != "space" || m.First(Bottom) != "pgdn" || m.First(Editor) != "" || m.First("missing") != "" {
		t.Errorf("first: %q %q %q", m.First(PageDown), m.First(Bottom), m.First(Editor))
	}
}

func TestEveryActionHasScreensAndHelp(t *testing.T) {
	seen := map[string]bool{}
	for _, a := range Actions {
		if seen[a.Name] || a.Help == "" || len(a.Screens) == 0 {
			t.Errorf("action %+v: duplicate, or missing help or screens", a)
		}
		seen[a.Name] = true
	}
}

func TestValidateFzf(t *testing.T) {
	if err := ValidateFzf(FzfDefaults()); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		edit Map
		want string
	}{
		{"unknown", Map{"qiut": {"alt-q"}}, `unknown action "qiut"`},
		{"not in fzf", Map{Up: {"alt-k"}}, "up is not available in fzf"},
		{"plain letter", Map{StatusDone: {"d"}}, `"d" would stop typing it into the query`},
		{"leaves fzf", Map{Note: {"esc"}}, "esc leaves fzf"},
		{"same screen", Map{Note: {"alt-d"}}, `"alt-d" is bound to both status_done and note on the tasks screen`},
		{"disjoint screens share", Map{Rescan: {"alt-x"}, Note: {"alt-x"}}, ""},
		{"several keys", Map{StatusDone: {"alt-d", "ctrl-d"}}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := FzfDefaults()
			for k, v := range tc.edit {
				m[k] = v
			}
			err := ValidateFzf(m)
			switch {
			case tc.want == "" && err != nil:
				t.Errorf("unexpected error: %v", err)
			case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
				t.Errorf("error %v, want %q", err, tc.want)
			}
		})
	}
}

func TestFzfActionsScreens(t *testing.T) {
	for _, a := range FzfActions() {
		if len(a.Screens) == 0 {
			t.Errorf("%s has no fzf screen", a.Name)
		}
		for _, s := range a.Screens {
			if s != Dashboard && s != Tasks {
				t.Errorf("%s on %s", a.Name, s)
			}
		}
	}
}
