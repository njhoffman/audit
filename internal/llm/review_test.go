package llm

import (
	"strings"
	"testing"

	"github.com/njhoffman/audit/internal/finding"
)

func TestReviewRequestAndFindings(t *testing.T) {
	existing := []finding.Finding{{Command: "repos", Check: "repo.dirty", Subject: "/r/a", Severity: finding.Notice, Message: "dirty"}}
	req := ReviewRequest("repos", existing, nil, 5)
	if req.Schema == "" || !strings.Contains(req.Prompt, `"check": "repo.dirty"`) || !strings.Contains(req.System, "NOT already cover") {
		t.Errorf("request: %+v", req)
	}
	rv := Review{Points: []ReviewPoint{
		{Title: "Already reported", Subject: "/r/a", Severity: "notice"},
		{Title: "Back up ~/notes", Subject: "", Severity: "notice", Details: []string{"no remote"}, Fix: "git remote add"},
		{Title: "Back up ~/notes!", Severity: "info"},
		{Title: "  ", Subject: "x"},
		{Title: "Prune stale clones", Subject: "/r/b", Severity: "bogus"},
	}}
	fs := ReviewFindings("repos", rv, existing)
	if len(fs) != 2 {
		t.Fatalf("findings %+v", fs)
	}
	if f := fs[0]; f.Check != CheckAIReview || f.Subject != "back-up-notes" || f.Kind != finding.Suggestion || f.Severity != finding.Notice ||
		f.Hint != "git remote add" || f.Details[0] != "no remote" {
		t.Errorf("first: %+v", f)
	}
	if f := fs[1]; f.Subject != "/r/b" || f.Severity != finding.Info {
		t.Errorf("an unknown severity is info: %+v", f)
	}
}
