package core

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/njhoffman/audit/internal/llm"
	"github.com/njhoffman/audit/internal/packages"
	"github.com/njhoffman/audit/internal/progress"
)

type memTags struct {
	memMeta
	tags    map[string][]string
	failTag error
}

func (s *memTags) ReplaceAITags(_ context.Context, manager, id string, tags []string) error {
	if s.failTag != nil {
		return s.failTag
	}
	s.tags[manager+":"+id] = tags
	return nil
}

// batchAsker answers each prompt with answer(n), n counting from 0.
type batchAsker struct {
	n       int
	refresh []bool
	answer  func(n int, prompt string) (string, error)
}

func (a *batchAsker) Ask(_ context.Context, req llm.Request, refresh bool) (*llm.Response, error) {
	a.refresh = append(a.refresh, refresh)
	text, err := a.answer(a.n, req.Prompt)
	a.n++
	if err != nil {
		return nil, err
	}
	return &llm.Response{Text: text}, nil
}

func tagItems(n int) ([]packages.Item, map[string]packages.Meta) {
	var items []packages.Item
	metas := map[string]packages.Meta{}
	for i := range n {
		name := fmt.Sprintf("p%03d", i)
		m := packages.Meta{Manager: "uv", ID: name}
		metas[packages.MetaKey("uv", name)] = m
		items = append(items, packages.Item{Package: packages.Package{Manager: "uv", Name: name}, Meta: &m})
	}
	return items, metas
}

func TestAITag(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	items, metas := tagItems(TagBatch + 2)
	st := &memTags{memMeta: memMeta{m: metas}, tags: map[string][]string{}}
	ai := &batchAsker{answer: func(n int, prompt string) (string, error) {
		if n == 1 {
			return "", errors.New("rate limited")
		}
		if !strings.Contains(prompt, "uv:p000") {
			t.Errorf("first batch prompt lacks its packages")
		}
		return `{"uv:p000": ["cli", "nonsense"], "uv:p001": ["linter"]}`, nil
	}}
	n, err := AITag(ctx, items, TagOptions{Store: st, AI: ai, Vocab: []string{"cli", "linter"}, Refresh: true, Now: now}, progress.Nop)
	if n != 2 || err == nil || !strings.Contains(err.Error(), "rate limited") {
		t.Fatalf("a failed batch is reported and the rest kept: %d %v", n, err)
	}
	if ai.n != 2 || !ai.refresh[0] {
		t.Errorf("two batches, refreshed: %d %v", ai.n, ai.refresh)
	}
	if strings.Join(st.tags["uv:p000"], ",") != "cli" || strings.Join(st.tags["uv:p001"], ",") != "linter" {
		t.Errorf("tags %v", st.tags)
	}
	if len(st.saved) != 2 || !st.saved[0].TaggedAt.Equal(now) {
		t.Errorf("TaggedAt saved: %+v", st.saved)
	}

	if n, err := AITag(ctx, nil, TagOptions{}, progress.Nop); n != 0 || err != nil {
		t.Errorf("nothing to tag: %d %v", n, err)
	}
	st.failTag = errors.New("disk full")
	ai.n = 0
	if _, err := AITag(ctx, items[:1], TagOptions{Store: st, AI: ai, Vocab: []string{"cli"}}, progress.Nop); err == nil || err.Error() != "disk full" {
		t.Errorf("a store error stops it: %v", err)
	}
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	ai = &batchAsker{answer: func(int, string) (string, error) { return "", errors.New("killed") }}
	if _, err := AITag(cctx, items[:1], TagOptions{Store: st, AI: ai}, progress.Nop); !errors.Is(err, context.Canceled) {
		t.Errorf("canceled: %v", err)
	}
}
