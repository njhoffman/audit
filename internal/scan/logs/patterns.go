package logs

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/njhoffman/audit/internal/scan"
)

// Normalization regexes collapse high-cardinality tokens (numbers, addrs,
// IPs, paths) so semantically-identical messages bucket together.
var (
	reHexAddr = regexp.MustCompile(`0x[0-9a-fA-F]+`)
	reUUID    = regexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`)
	reIPv4    = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b`)
	// Loose IPv6 match: 3+ colon-separated hex groups (covers shorthand
	// forms like 2001:db8::1 where adjacent groups are empty).
	reIPv6 = regexp.MustCompile(`\b[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{0,4}){2,}\b`)
	rePID  = regexp.MustCompile(`\[\d+\]`)
	reNum  = regexp.MustCompile(`\b\d+\b`)
	rePath = regexp.MustCompile(`/(?:[A-Za-z0-9._-]+/)+[A-Za-z0-9._-]+`)
)

// Normalize a log message so duplicates collapse. Order matters: replace
// the most specific tokens first (UUIDs, IPs) before the catch-all numeric
// collapse.
func Normalize(msg string) string {
	s := msg
	s = reUUID.ReplaceAllString(s, "<uuid>")
	s = reHexAddr.ReplaceAllString(s, "<hex>")
	s = reIPv4.ReplaceAllString(s, "<ip>")
	s = reIPv6.ReplaceAllString(s, "<ip>")
	s = rePID.ReplaceAllString(s, "[<pid>]")
	s = rePath.ReplaceAllString(s, "<path>")
	s = reNum.ReplaceAllString(s, "<n>")
	s = strings.Join(strings.Fields(s), " ")
	return s
}

// TopBuckets returns the top-N normalized patterns by count, with a sample
// raw message preserved per bucket for the human report.
func TopBuckets(entries []Entry, n int) []Bucket {
	if n <= 0 {
		return nil
	}
	type acc struct {
		count  int
		sample string
	}
	by := map[string]*acc{}
	order := []string{}
	for _, e := range entries {
		key := Normalize(e.Message)
		if key == "" {
			continue
		}
		if a, ok := by[key]; ok {
			a.count++
		} else {
			by[key] = &acc{count: 1, sample: e.Message}
			order = append(order, key)
		}
	}
	out := make([]Bucket, 0, len(order))
	for _, k := range order {
		out = append(out, Bucket{Normalized: k, Count: by[k].count, Sample: by[k].sample})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Normalized < out[j].Normalized
	})
	if n < len(out) {
		out = out[:n]
	}
	return out
}

// Rule is a single high-priority pattern that produces a finding when matched.
type Rule struct {
	Name     string
	Pattern  *regexp.Regexp
	Severity scan.Severity
	Subject  string // human-friendly subject prefix
}

// Rules covers patterns that warrant a finding regardless of how often they
// appear. Source-agnostic — kernel-only patterns still match journal entries
// that quote them.
var Rules = []Rule{
	{
		Name:     "kernel-panic",
		Pattern:  regexp.MustCompile(`(?i)kernel panic`),
		Severity: scan.SeverityCritical,
		Subject:  "kernel panic detected",
	},
	{
		Name:     "oom-kill",
		Pattern:  regexp.MustCompile(`(?i)Out of memory: Kill(?:ed)? process`),
		Severity: scan.SeverityCritical,
		Subject:  "OOM killer activated",
	},
	{
		Name: "hardware-error",
		// Real hardware events: literal MCE/EDAC tokens with adjacent
		// error markers. Case-sensitive on purpose: "edac" inside a
		// debug payload (e.g. dist-upgrade logs that quote package
		// names) was triggering the case-insensitive form.
		Pattern:  regexp.MustCompile(`Hardware Error\b|\bMCE:\s|\bEDAC\b[^\n]{0,80}\b(?:UE|CE|error)\b`),
		Severity: scan.SeverityError,
		Subject:  "hardware error reported",
	},
	{
		Name: "kernel-bug",
		// Kernel oops-style BUG markers are always uppercase. Keeping
		// the (?i) flag matched Xorg's "client bug:" debug wording.
		Pattern:  regexp.MustCompile(`\bBUG:|kernel BUG at|general protection fault`),
		Severity: scan.SeverityError,
		Subject:  "kernel bug or fault",
	},
	{
		Name:     "segfault",
		Pattern:  regexp.MustCompile(`(?i)segfault at|Segmentation fault`),
		Severity: scan.SeverityWarning,
		Subject:  "userspace segfault",
	},
	{
		Name:     "io-error",
		Pattern:  regexp.MustCompile(`(?i)\bI/O error\b|end_request: I/O error|critical medium error`),
		Severity: scan.SeverityError,
		Subject:  "I/O error",
	},
	{
		Name:     "filesystem-error",
		Pattern:  regexp.MustCompile(`(?i)EXT4-fs error|Btrfs:.*(?:corrupt|error)|XFS \(.*\): Corruption`),
		Severity: scan.SeverityError,
		Subject:  "filesystem error",
	},
	{
		Name:     "auth-failure",
		Pattern:  regexp.MustCompile(`(?i)authentication failure|Failed password for|sudo:.*authentication failure`),
		Severity: scan.SeverityWarning,
		Subject:  "authentication failure",
	},
	{
		Name:     "sudo-not-in-sudoers",
		Pattern:  regexp.MustCompile(`(?i)NOT in sudoers`),
		Severity: scan.SeverityWarning,
		Subject:  "sudo invocation by non-sudoer",
	},
	{
		Name:     "audit-failed",
		Pattern:  regexp.MustCompile(`(?i)audit:.*res=failed|res=failed.*audit:`),
		Severity: scan.SeverityNotice,
		Subject:  "audit subsystem reported failure",
	},
}

// ApplyRules returns a finding for each rule that matches at least one
// entry. Multiple matches collapse into a single finding with a count.
func ApplyRules(src Source, entries []Entry) []scan.Finding {
	type hit struct {
		rule   Rule
		count  int
		sample Entry
	}
	hits := map[string]*hit{}
	order := []string{}

	for _, e := range entries {
		for _, r := range Rules {
			if r.Pattern.MatchString(e.Message) {
				if h, ok := hits[r.Name]; ok {
					h.count++
				} else {
					hits[r.Name] = &hit{rule: r, count: 1, sample: e}
					order = append(order, r.Name)
				}
			}
		}
	}

	out := make([]scan.Finding, 0, len(order))
	for _, name := range order {
		h := hits[name]
		out = append(out, scan.Finding{
			Severity: h.rule.Severity,
			Check:    h.rule.Name,
			Subject:  string(src),
			Detail:   fmt.Sprintf("%s (%d hit(s)); sample: %q", h.rule.Subject, h.count, truncate(h.sample.Message, 240)),
		})
	}
	return out
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
