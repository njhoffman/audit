package registry

import (
	"context"
	"sync"
	"time"

	"github.com/njhoffman/audit/internal/packages"
)

// Looker answers registry lookups; *Client is the real one.
type Looker interface {
	Lookup(ctx context.Context, p packages.Package, prev *packages.Meta, describe bool) (packages.Meta, bool, error)
}

// Options control a refresh.
type Options struct {
	// MaxAge is how old version data may be before it is fetched again.
	MaxAge time.Duration
	// MetadataMaxAge is how old descriptions may be before they are fetched
	// again, where that costs extra requests (crates.io API, GitHub).
	MetadataMaxAge time.Duration
	Concurrency    int
	// Timeout bounds one package's lookup.
	Timeout time.Duration
	// Force fetches everything regardless of age.
	Force bool
	Now   time.Time
	// OnDone is called after each lookup, from the worker goroutine.
	OnDone func(p packages.Package, err error)
}

// Stats summarize a refresh.
type Stats struct {
	Checked int // looked up, successfully or not
	Failed  int
	Fresh   int // cache was recent enough
}

// Refresh looks up every package with a registry whose cached data is stale
// and returns the updated entries; unchanged cache entries are not returned.
// A failed lookup keeps the previous answer, records the error and counts as
// checked, so it is retried after MaxAge rather than on every run.
func Refresh(ctx context.Context, l Looker, pkgs []packages.Package, cache map[string]packages.Meta, o Options) ([]packages.Meta, Stats) {
	if o.Now.IsZero() {
		o.Now = time.Now()
	}
	type job struct {
		p        packages.Package
		prev     *packages.Meta
		describe bool
	}
	var jobs []job
	var st Stats
	seen := map[string]bool{}
	for _, p := range pkgs {
		if p.Registry() == "" || seen[p.Key()] {
			continue
		}
		seen[p.Key()] = true
		var prev *packages.Meta
		if m, ok := cache[p.Key()]; ok {
			prev = &m
		}
		if !o.Force && prev != nil && !prev.CheckedAt.IsZero() && o.Now.Sub(prev.CheckedAt) < o.MaxAge && prev.Installed == p.Version {
			st.Fresh++
			continue
		}
		describe := o.Force || prev == nil || prev.DescribedAt.IsZero() || o.Now.Sub(prev.DescribedAt) >= o.MetadataMaxAge
		jobs = append(jobs, job{p, prev, describe})
	}

	out := make([]packages.Meta, len(jobs))
	errs := make([]error, len(jobs))
	work := make(chan int)
	var wg sync.WaitGroup
	for range max(o.Concurrency, 1) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range work {
				j := jobs[i]
				lctx, cancel := ctx, context.CancelFunc(func() {})
				if o.Timeout > 0 {
					lctx, cancel = context.WithTimeout(ctx, o.Timeout)
				}
				m, described, err := l.Lookup(lctx, j.p, j.prev, j.describe)
				cancel()
				if err != nil && ctx.Err() != nil {
					continue // interrupted: keep the cache as it was
				}
				out[i], errs[i] = merge(j.p, j.prev, m, described, err, o.Now), err
				if o.OnDone != nil {
					o.OnDone(j.p, err)
				}
			}
		}()
	}
	for i := range jobs {
		if ctx.Err() != nil {
			break
		}
		work <- i
	}
	close(work)
	wg.Wait()

	var done []packages.Meta
	for i, m := range out {
		if m.Manager == "" {
			continue // not reached before cancellation
		}
		st.Checked++
		if errs[i] != nil {
			st.Failed++
		}
		done = append(done, m)
	}
	return done, st
}

// merge combines a lookup with the cached entry.
func merge(p packages.Package, prev *packages.Meta, m packages.Meta, described bool, err error, now time.Time) packages.Meta {
	if err != nil {
		if prev != nil {
			m = *prev
		} else {
			m = packages.Meta{Installed: p.Version}
		}
		m.Manager, m.ID, m.Registry = p.Manager, p.ID(), p.Registry()
		m.Error, m.CheckedAt = err.Error(), now
		return m
	}
	m.Manager, m.ID, m.Registry, m.Installed, m.CheckedAt, m.Error = p.Manager, p.ID(), p.Registry(), p.Version, now, ""
	if described {
		m.DescribedAt = now
	} else if prev != nil {
		m.Description, m.Homepage, m.License, m.Keywords = prev.Description, prev.Homepage, prev.License, prev.Keywords
		m.Archived, m.DescribedAt = prev.Archived, prev.DescribedAt
		if m.Repo == "" {
			m.Repo = prev.Repo
		}
	}
	if prev != nil {
		m.TaggedAt = prev.TaggedAt
		if m.LatestAt.IsZero() && m.Latest == prev.Latest {
			m.LatestAt = prev.LatestAt
		}
		if m.Deprecated == "" && !described {
			m.Deprecated = prev.Deprecated
		}
	}
	return m
}
