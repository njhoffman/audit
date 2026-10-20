---
description: Pick a TODO.md item in a tmux popup (todo-fzf)
allowed-tools: Bash(tmux display-popup:*), Bash(tmux display-message:*), Bash(echo:*)
---

!`tmux display-popup -E -w 90% -h 80% -d "$PWD" -t "${TMUX_PANE:-$(tmux display-message -p '#{pane_id}')}" ~/.shell/scripts/todo-fzf; echo "todo-fzf popup closed (exit $?)"`

The todo-fzf popup above ran in tmux and has closed; whatever the user picked
opened in their editor there, not here. Reply with one short line. If the exit
status is non-zero, say the popup failed and suggest running
`~/.shell/scripts/todo-fzf` directly in a terminal.
