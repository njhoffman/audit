package finding

import "fmt"

// Check is one named check over a command's scan state S.
type Check[S any] struct {
	ID string
	Fn func(S) []Finding
}

// RunChecks runs every check against s and returns the findings sorted most
// serious first. Each finding gets the command, the check id when it has none,
// and Kind Issue when it has no kind. A check that panics reports itself as an
// error finding instead of aborting the others.
func RunChecks[S any](command string, s S, checks []Check[S]) []Finding {
	var out []Finding
	for _, c := range checks {
		for _, f := range runOne(c, s) {
			f.Command = command
			if f.Check == "" {
				f.Check = c.ID
			}
			if f.Kind == "" {
				f.Kind = Issue
			}
			out = append(out, f)
		}
	}
	Sort(out)
	return out
}

func runOne[S any](c Check[S], s S) (fs []Finding) {
	defer func() {
		if r := recover(); r != nil {
			fs = []Finding{{Check: c.ID, Severity: Error, Message: fmt.Sprintf("check crashed: %v", r)}}
		}
	}()
	return c.Fn(s)
}
