package core

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/njhoffman/audit/internal/llm"
	"github.com/njhoffman/audit/internal/packages"
	"github.com/njhoffman/audit/internal/progress"
)

// TagBatch is how many packages one tagging prompt covers.
const TagBatch = 50

// TagStore holds the registry cache and the AI tags (implemented by
// *store.Store).
type TagStore interface {
	MetaStore
	ReplaceAITags(ctx context.Context, manager, id string, tags []string) error
}

// Asker answers prompts (implemented by *llm.Client).
type Asker interface {
	Ask(ctx context.Context, req llm.Request, refresh bool) (*llm.Response, error)
}

// TagOptions configure AITag.
type TagOptions struct {
	Store TagStore
	AI    Asker
	// Vocab is the tag vocabulary (packages.tags).
	Vocab []string
	// Refresh asks again instead of answering from the AI cache.
	Refresh bool
	// Now stamps TaggedAt; zero means time.Now.
	Now time.Time
}

// AITag asks the AI for tags of items in batches of TagBatch, replaces
// each answered package's AI tags and stamps its TaggedAt. A batch that
// fails is reported in the joined error and the others go on; a canceled
// context or a store error stops it. It returns how many were tagged.
func AITag(ctx context.Context, items []packages.Item, o TagOptions, rep progress.Reporter) (int, error) {
	if len(items) == 0 {
		return 0, nil
	}
	now := o.Now
	if now.IsZero() {
		now = time.Now()
	}
	metas, err := o.Store.PackageMeta(ctx)
	if err != nil {
		return 0, err
	}
	rep.Phase("asking the AI for tags", (len(items)+TagBatch-1)/TagBatch)
	defer rep.Done()
	tagged := 0
	var updated []packages.Meta
	var errs []error
	for start := 0; start < len(items); start += TagBatch {
		batch := items[start:min(start+TagBatch, len(items))]
		resp, err := o.AI.Ask(ctx, llm.Request{System: packages.TagSystem, Prompt: packages.TagPrompt(batch, o.Vocab)}, o.Refresh)
		rep.Step(fmt.Sprintf("%d package(s)", len(batch)))
		if err != nil {
			if ctx.Err() != nil {
				return tagged, ctx.Err()
			}
			errs = append(errs, err)
			continue
		}
		answer, err := packages.ParseTagAnswer(resp.Text, batch, o.Vocab)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		keys := make([]string, 0, len(answer))
		for k := range answer {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		for _, k := range keys {
			m := metas[k]
			if err := o.Store.ReplaceAITags(ctx, m.Manager, m.ID, answer[k]); err != nil {
				return tagged, err
			}
			m.TaggedAt = now
			updated = append(updated, m)
			tagged++
		}
	}
	if err := o.Store.SavePackageMeta(ctx, updated); err != nil {
		return tagged, err
	}
	return tagged, errors.Join(errs...)
}
