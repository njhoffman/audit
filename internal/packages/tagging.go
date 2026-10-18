package packages

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// MaxAITags caps the tags kept per package from one answer.
const MaxAITags = 4

// TagSystem is the system prompt for AI tagging.
const TagSystem = `You classify software packages installed on a developer workstation.
Answer with a single JSON object and nothing else.`

// TagPrompt asks for tags from vocab for items. Packages are keyed by
// manager:id so the answer can be matched back.
func TagPrompt(items []Item, vocab []string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Choose 1 to %d tags for each package below, only from this vocabulary:\n%s\n\n",
		MaxAITags, strings.Join(vocab, ", "))
	b.WriteString("Use what the package is for, not the language it is written in. Answer as\n")
	b.WriteString(`{"<key>": ["tag", ...], ...}` + " with every key listed.\n\nPackages (key | description | keywords):\n")
	for _, it := range items {
		desc, kw := "", ""
		if it.Meta != nil {
			desc, kw = it.Meta.Description, strings.Join(it.Meta.Keywords, ", ")
		}
		if desc == "" {
			desc = "(no description)"
		}
		fmt.Fprintf(&b, "%s | %s | %s\n", it.Key(), desc, kw)
	}
	return b.String()
}

// ParseTagAnswer reads the model's answer: tags per key, restricted to vocab
// and to the keys asked about. Keys the answer leaves out are absent from
// the result, so they are asked about again next time.
func ParseTagAnswer(text string, items []Item, vocab []string) (map[string][]string, error) {
	start, end := strings.Index(text, "{"), strings.LastIndex(text, "}")
	if start < 0 || end < start {
		return nil, errors.New("the answer has no JSON object")
	}
	var raw map[string][]string
	if err := json.Unmarshal([]byte(text[start:end+1]), &raw); err != nil {
		return nil, fmt.Errorf("the answer is not a JSON object of tag lists: %w", err)
	}
	asked := map[string]bool{}
	for _, it := range items {
		asked[it.Key()] = true
	}
	out := map[string][]string{}
	for key, tags := range raw {
		if !asked[key] {
			continue
		}
		kept := []string{}
		for _, t := range tags {
			t = NormalizeTag(t)
			if slices.Contains(vocab, t) && !slices.Contains(kept, t) && len(kept) < MaxAITags {
				kept = append(kept, t)
			}
		}
		out[key] = kept
	}
	return out, nil
}
