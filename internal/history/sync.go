package history

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

// SyncPlan is a zsh history file rebuilt from histdb, not yet written.
// Command text stays in memory and is never serialized.
type SyncPlan struct {
	Path string `json:"path"`
	// HistDB counts histdb's entries, File the file's current ones.
	HistDB int `json:"histdb"`
	File   int `json:"file"`
	// Refusal says why the plan must not be applied without force ("" when
	// it may): histdb is empty, or holds fewer entries than the file, so
	// replacing the file would drop commands histdb never recorded.
	Refusal     string `json:"refusal,omitempty"`
	original    []byte
	replacement []byte
	info        os.FileInfo
}

// PlanSync reads the zsh history at path and histdb at dbPath and builds the
// replacement: one extended-history record per histdb entry, with its start
// time and duration, metafied as zsh writes its history.
func PlanSync(ctx context.Context, dbPath, path string) (SyncPlan, error) {
	p := SyncPlan{Path: path}
	if dbPath == "" {
		return p, errors.New("shell_history.histdb is not set")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return p, err
	}
	if err := safeHistory(info); err != nil {
		return p, err
	}
	f, err := os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW, 0) // #nosec G304 -- configured history path
	if err != nil {
		return p, err
	}
	body, err := io.ReadAll(f)
	_ = f.Close()
	if err != nil {
		return p, err
	}
	p.info, p.original = info, body
	p.File = len(parse(string(body), "zsh"))

	if _, err := os.Stat(dbPath); err != nil {
		return p, fmt.Errorf("histdb %s: %w", dbPath, err)
	}
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(dbPath)+"?mode=ro")
	if err != nil {
		return p, err
	}
	defer func() { _ = db.Close() }()
	rows, err := db.QueryContext(ctx, `SELECT h.start_time, coalesce(h.duration,0), c.argv FROM history h JOIN commands c ON c.id=h.command_id ORDER BY h.start_time, h.id`)
	if err != nil {
		return p, fmt.Errorf("read histdb: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out strings.Builder
	for rows.Next() {
		var started, duration int64
		var command string
		if err := rows.Scan(&started, &duration, &command); err != nil {
			return p, err
		}
		if !utf8.ValidString(command) {
			return p, errors.New("histdb contains invalid UTF-8 command data")
		}
		command = strings.ReplaceAll(metafy(command), "\n", "\\\n")
		fmt.Fprintf(&out, ": %d:%d;%s\n", started, duration, command)
		p.HistDB++
	}
	if err := rows.Err(); err != nil {
		return p, err
	}
	p.replacement = []byte(out.String())
	switch {
	case p.HistDB == 0:
		p.Refusal = "histdb has no entries; replacing the file would empty it"
	case p.HistDB < p.File:
		p.Refusal = fmt.Sprintf("histdb has %d entries and the file %d; replacing it would drop the %d histdb never recorded (pass --force to accept that)",
			p.HistDB, p.File, p.File-p.HistDB)
	}
	return p, nil
}

// ApplySync writes the plan under the same locks and checks as a prune and
// returns the backup's path. A plan with a Refusal is applied only with
// force, and never when histdb is empty.
func ApplySync(ctx context.Context, p SyncPlan, force bool) (string, error) {
	if p.info == nil {
		return "", errors.New("empty history sync plan")
	}
	if p.HistDB == 0 {
		return "", errors.New(p.Refusal)
	}
	if p.Refusal != "" && !force {
		return "", errors.New(p.Refusal)
	}
	return replaceHistory(ctx, p.Path, p.info, p.original, p.replacement)
}

// metafy escapes the bytes zsh reserves internally, as zsh itself does when
// it writes a history file (measured against zsh 5.9: 0x83 through 0xa2
// become 0x83 followed by the byte xor 0x20). Unescaped, zsh would misread a
// command holding them, such as "ă" (c4 83) or "→" (e2 86 92).
func metafy(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 0x83 && c <= 0xa2 {
			b.WriteByte(0x83)
			c ^= 0x20
		}
		b.WriteByte(c)
	}
	return b.String()
}

// FormatOf reads the start of the history at path and names its format:
// zsh, bash or fish, as Scan and PlanPrune would read it.
func FormatOf(path string) (string, error) {
	f, err := os.Open(path) // #nosec G304 -- configured history path
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	head := make([]byte, 4096)
	n, err := io.ReadFull(f, head)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return "", err
	}
	return formatOf(path, head[:n]), nil
}
