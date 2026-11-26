package finding

// Delta is what changed between two sets of findings, keyed by Key (command,
// check and subject, as ignore rules and tasks are).
type Delta struct {
	// Added are in the newer set only.
	Added []Finding `json:"added"`
	// Resolved are in the older set only.
	Resolved []Finding `json:"resolved"`
	// Changed are in both with another severity, newer finding first.
	Changed []Change `json:"changed"`
	// Unchanged counts findings in both at the same severity.
	Unchanged int `json:"unchanged"`
}

// Change is one finding whose severity moved.
type Change struct {
	From Severity `json:"from"`
	Finding
}

// Empty reports whether nothing was added, resolved or changed.
func (d Delta) Empty() bool { return len(d.Added) == 0 && len(d.Resolved) == 0 && len(d.Changed) == 0 }

// Diff compares older with newer. Each list is sorted like Sort. A key that
// repeats within one set counts once, as its first finding.
func Diff(older, newer []Finding) Delta {
	before := make(map[string]Finding, len(older))
	for _, f := range older {
		if _, ok := before[f.Key()]; !ok {
			before[f.Key()] = f
		}
	}
	d := Delta{Added: []Finding{}, Resolved: []Finding{}, Changed: []Change{}}
	seen := make(map[string]bool, len(newer))
	for _, f := range newer {
		k := f.Key()
		if seen[k] {
			continue
		}
		seen[k] = true
		old, ok := before[k]
		switch {
		case !ok:
			d.Added = append(d.Added, f)
		case old.Severity != f.Severity:
			d.Changed = append(d.Changed, Change{From: old.Severity, Finding: f})
		default:
			d.Unchanged++
		}
	}
	for _, f := range older {
		if k := f.Key(); !seen[k] {
			seen[k] = true
			d.Resolved = append(d.Resolved, f)
		}
	}
	Sort(d.Added)
	Sort(d.Resolved)
	changed := make([]Finding, len(d.Changed))
	from := make(map[string]Severity, len(d.Changed))
	for i, c := range d.Changed {
		changed[i], from[c.Key()] = c.Finding, c.From
	}
	Sort(changed)
	for i, f := range changed {
		d.Changed[i] = Change{From: from[f.Key()], Finding: f}
	}
	return d
}
