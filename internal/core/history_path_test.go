package core

import (
	"testing"

	"github.com/njhoffman/audit/internal/config"
	"github.com/njhoffman/audit/internal/exec"
)

func TestHistoryPathsAreAbsolute(t *testing.T) {
	home := "/home/u"
	unset := &exec.Env{Home: home, Vars: map[string]string{"HOME": home}}
	set := &exec.Env{Home: home, Vars: map[string]string{"HOME": home, "XDG_DATA_HOME": "/data", "HIST": "/h"}}
	for _, tc := range []struct {
		env  *exec.Env
		in   string
		want string
	}{
		{unset, "~/.zsh_history", "/home/u/.zsh_history"},
		{unset, "~", "/home/u"},
		{unset, ".bash_history", "/home/u/.bash_history"},
		{unset, "hist/../.zsh_history", "/home/u/.zsh_history"},
		{unset, "$XDG_DATA_HOME/fish/fish_history", "/home/u/.local/share/fish/fish_history"},
		{unset, "${XDG_DATA_HOME}/fish/fish_history", "/home/u/.local/share/fish/fish_history"},
		{set, "$XDG_DATA_HOME/fish/fish_history", "/data/fish/fish_history"},
		{set, "${XDG_DATA_HOME}/fish/fish_history", "/data/fish/fish_history"},
		{set, "$HIST/zsh", "/h/zsh"},
		{unset, "$HOME/.zsh_history", "/home/u/.zsh_history"},
		{unset, "", ""},
	} {
		if got := historyPath(tc.env, tc.in); got != tc.want {
			t.Errorf("historyPath(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	cfg := &config.Config{ShellHistory: config.ShellHistoryConfig{Files: []string{"rel/h", "${XDG_DATA_HOME}/f"}, HistDB: "~/.histdb/z.db"}}
	o := NewHistory(cfg, unset).Options
	if o.Files[0] != "/home/u/rel/h" || o.Files[1] != "/home/u/.local/share/f" || o.HistDB != "/home/u/.histdb/z.db" {
		t.Errorf("NewHistory: %+v %q", o.Files, o.HistDB)
	}
}
