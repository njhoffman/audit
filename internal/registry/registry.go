// Package registry looks packages up in their public registries (PyPI, npm,
// crates.io, the Go module proxy, rubygems.org and GitHub) and refreshes the
// cached packages.Meta the package checks read.
package registry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/mod/module"

	"github.com/njhoffman/audit/internal/exec"
	"github.com/njhoffman/audit/internal/packages"
)

// Bases are the registry endpoints; tests point them at an httptest server.
type Bases struct {
	PyPI        string
	Npm         string
	CratesIndex string
	CratesAPI   string
	// GoProxy overrides GOPROXY when set.
	GoProxy  string
	Rubygems string
	// Node and GoDL are the runtime release lists.
	Node string
	GoDL string
}

// DefaultBases are the public registries.
func DefaultBases() Bases {
	return Bases{
		PyPI:        "https://pypi.org",
		Npm:         "https://registry.npmjs.org",
		CratesIndex: "https://index.crates.io",
		CratesAPI:   "https://crates.io",
		Rubygems:    "https://rubygems.org",
		Node:        "https://nodejs.org/dist/index.json",
		GoDL:        "https://go.dev/dl/?mode=json",
	}
}

// DefaultGoProxy is used when GOPROXY is unset.
const DefaultGoProxy = "https://proxy.golang.org,direct"

// Client fetches registry data.
type Client struct {
	HTTP      *http.Client
	UserAgent string
	Base      Bases
	// Env runs gh and supplies GOPROXY, GOPRIVATE and GONOPROXY.
	Env     *exec.Env
	Timeout time.Duration
	// Intervals spaces requests to one host; crates.io asks API clients for
	// at most one request a second.
	Intervals map[string]time.Duration

	mu   sync.Mutex
	next map[string]time.Time
}

// NewClient returns a client for the public registries.
func NewClient(env *exec.Env, userAgent string, timeout time.Duration) *Client {
	return &Client{
		HTTP: &http.Client{Timeout: timeout}, UserAgent: userAgent, Base: DefaultBases(), Env: env, Timeout: timeout,
		Intervals: map[string]time.Duration{"crates.io": time.Second},
	}
}

// ErrNotFound is returned when the registry does not know the package.
var ErrNotFound = errors.New("not found")

// wait blocks until host may be called again.
func (c *Client) wait(ctx context.Context, host string) error {
	every := c.Intervals[host]
	if every <= 0 {
		return nil
	}
	c.mu.Lock()
	if c.next == nil {
		c.next = map[string]time.Time{}
	}
	now := time.Now()
	at := c.next[host]
	if at.Before(now) {
		at = now
	}
	c.next[host] = at.Add(every)
	c.mu.Unlock()
	t := time.NewTimer(time.Until(at))
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func (c *Client) get(ctx context.Context, rawURL string) ([]byte, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	if err := c.wait(ctx, u.Host); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", c.UserAgent)
	req.Header.Set("Accept", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, err
	}
	switch {
	case resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone:
		return nil, ErrNotFound
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("%s: HTTP %d", u.Host, resp.StatusCode)
	}
	return body, nil
}

func (c *Client) getJSON(ctx context.Context, rawURL string, v any) error {
	body, err := c.get(ctx, rawURL)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(body, v); err != nil {
		return fmt.Errorf("unexpected response from %s: %w", rawURL, err)
	}
	return nil
}

// gh runs `gh api path` and decodes its JSON output.
func (c *Client) gh(ctx context.Context, path string, v any) error {
	if c.Env == nil {
		return errors.New("gh is not available")
	}
	res := c.Env.Run(ctx, "gh", []string{"api", path}, exec.Options{Timeout: c.Timeout})
	switch {
	case res.Code == exec.ExitNotFound && strings.Contains(res.Stderr, "command not found"):
		return errors.New("gh is not installed")
	case strings.Contains(res.Stderr, "HTTP 404") || strings.Contains(res.Stdout, `"status":"404"`):
		return ErrNotFound
	case res.Code == exec.ExitTimeout:
		return fmt.Errorf("gh api %s timed out", path)
	case res.Code != 0:
		msg, _, _ := strings.Cut(strings.TrimSpace(res.Stderr), "\n")
		return fmt.Errorf("gh api %s: %s", path, msg)
	}
	if err := json.Unmarshal([]byte(res.Stdout), v); err != nil {
		return fmt.Errorf("unexpected output from gh api %s: %w", path, err)
	}
	return nil
}

// Lookup asks p's registry about it. prev is the cached entry, if any.
// describe asks for the descriptive fields (description, repo, license...)
// where they cost an extra request; described reports whether they were
// filled, so the caller keeps the cached ones otherwise.
func (c *Client) Lookup(ctx context.Context, p packages.Package, prev *packages.Meta, describe bool) (m packages.Meta, described bool, err error) {
	switch p.Registry() {
	case packages.RegistryPyPI:
		m, err = c.pypi(ctx, p)
		return m, true, err
	case packages.RegistryNpm:
		m, err = c.npm(ctx, p, prev)
		return m, true, err
	case packages.RegistryCrates:
		return c.crates(ctx, p, prev, describe)
	case packages.RegistryGoProxy:
		return c.goproxy(ctx, p, describe)
	case packages.RegistryRubygems:
		m, err = c.rubygems(ctx, p)
		return m, true, err
	case packages.RegistryGitHub:
		return c.github(ctx, p, describe)
	}
	return m, false, errors.New("not from a registry")
}

func notFound(err error, where string) error {
	if errors.Is(err, ErrNotFound) {
		return fmt.Errorf("%w on %s", ErrNotFound, where)
	}
	return err
}

// Repository hosts recognized in project URLs.
var forges = []string{"github.com/", "gitlab.com/", "codeberg.org/", "bitbucket.org/", "sr.ht/"}

func isForge(u string) bool {
	for _, f := range forges {
		if strings.Contains(u, f) {
			return true
		}
	}
	return false
}

// cleanRepo turns the repository spellings registries use into a browsable
// URL: git+https://x.git, git://x, github:owner/repo.
func cleanRepo(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if owner, ok := strings.CutPrefix(s, "github:"); ok {
		s = "https://github.com/" + owner
	}
	if !strings.Contains(s, "://") && strings.Count(s, "/") == 1 && !strings.ContainsAny(s, " :@") {
		s = "https://github.com/" + s // npm shorthand owner/repo
	}
	s = strings.TrimPrefix(s, "git+")
	s = strings.Replace(s, "git://", "https://", 1)
	s = strings.Replace(s, "ssh://git@", "https://", 1)
	if rest, ok := strings.CutPrefix(s, "git@"); ok {
		s = "https://" + strings.Replace(rest, ":", "/", 1)
	}
	s, _, _ = strings.Cut(s, "#")
	s = strings.TrimSuffix(strings.TrimSuffix(s, "/"), ".git")
	return s
}

func parseTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}
	}
	return t
}

func splitKeywords(s string) []string {
	f := func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\n' }
	var out []string
	for _, k := range strings.FieldsFunc(s, f) {
		if k = strings.TrimSpace(k); k != "" {
			out = append(out, k)
		}
	}
	return out
}

// shortLicense drops license fields that hold the whole license text.
func shortLicense(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 80 || strings.Contains(s, "\n") {
		return ""
	}
	return s
}

func oneLine(s string) string { return strings.Join(strings.Fields(s), " ") }

type pypiResp struct {
	Info struct {
		Version           string            `json:"version"`
		Summary           string            `json:"summary"`
		HomePage          string            `json:"home_page"`
		License           string            `json:"license"`
		LicenseExpression string            `json:"license_expression"`
		Keywords          string            `json:"keywords"`
		ProjectURLs       map[string]string `json:"project_urls"`
		Classifiers       []string          `json:"classifiers"`
	} `json:"info"`
	Releases map[string][]struct {
		UploadTime string `json:"upload_time_iso_8601"`
		Yanked     bool   `json:"yanked"`
	} `json:"releases"`
}

// pypiInactive is the trove classifier for abandoned projects.
const pypiInactive = "Development Status :: 7 - Inactive"

func (c *Client) pypi(ctx context.Context, p packages.Package) (packages.Meta, error) {
	var r pypiResp
	if err := c.getJSON(ctx, c.Base.PyPI+"/pypi/"+url.PathEscape(p.Name)+"/json", &r); err != nil {
		return packages.Meta{}, notFound(err, "PyPI")
	}
	i := r.Info
	m := packages.Meta{Latest: i.Version, Description: oneLine(i.Summary), Keywords: splitKeywords(i.Keywords)}
	m.License = shortLicense(i.LicenseExpression)
	if m.License == "" {
		m.License = shortLicense(i.License)
	}
	for _, f := range r.Releases[i.Version] {
		if t := parseTime(f.UploadTime); !t.IsZero() && (m.LatestAt.IsZero() || t.Before(m.LatestAt)) {
			m.LatestAt = t
		}
	}
	if files := r.Releases[p.Version]; len(files) > 0 {
		m.InstalledYanked = true
		for _, f := range files {
			m.InstalledYanked = m.InstalledYanked && f.Yanked
		}
	}
	for _, cl := range i.Classifiers {
		if cl == pypiInactive {
			m.Deprecated = "marked \"" + pypiInactive + "\" on PyPI"
		}
	}
	m.Homepage = i.HomePage
	keys := make([]string, 0, len(i.ProjectURLs))
	for k := range i.ProjectURLs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, want := range []string{"source", "source code", "repository", "code", "github"} {
		for _, k := range keys {
			if strings.EqualFold(k, want) && m.Repo == "" {
				m.Repo = cleanRepo(i.ProjectURLs[k])
			}
		}
	}
	for _, k := range keys {
		u := i.ProjectURLs[k]
		if m.Repo == "" && isForge(u) {
			m.Repo = cleanRepo(u)
		}
		if m.Homepage == "" && strings.EqualFold(k, "homepage") {
			m.Homepage = u
		}
	}
	if m.Repo == "" && isForge(m.Homepage) {
		m.Repo = cleanRepo(m.Homepage)
	}
	return m, nil
}

type npmResp struct {
	Version     string          `json:"version"`
	Description string          `json:"description"`
	Homepage    string          `json:"homepage"`
	Repository  json.RawMessage `json:"repository"`
	License     json.RawMessage `json:"license"`
	Keywords    []string        `json:"keywords"`
	Deprecated  json.RawMessage `json:"deprecated"`
}

// stringOr reads a JSON value that is either a string or an object with the
// string under key.
func stringOr(raw json.RawMessage, key string) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var obj map[string]any
	if json.Unmarshal(raw, &obj) == nil {
		if v, ok := obj[key].(string); ok {
			return v
		}
	}
	return ""
}

func (c *Client) npm(ctx context.Context, p packages.Package, prev *packages.Meta) (packages.Meta, error) {
	// A scoped name keeps its @ and encodes the slash: @scope%2Fname.
	name := strings.ReplaceAll(url.PathEscape(p.Name), "%40", "@")
	var r npmResp
	if err := c.getJSON(ctx, c.Base.Npm+"/"+name+"/latest", &r); err != nil {
		return packages.Meta{}, notFound(err, "npm")
	}
	m := packages.Meta{
		Latest: r.Version, Description: oneLine(r.Description), Homepage: r.Homepage, Keywords: r.Keywords,
		Repo: cleanRepo(stringOr(r.Repository, "url")), License: shortLicense(stringOr(r.License, "type")),
	}
	if d := stringOr(r.Deprecated, ""); d != "" {
		m.Deprecated = oneLine(d)
	}
	// Release dates are only in the full document, which can be megabytes,
	// so it is fetched once per new release. A failure leaves the date
	// unknown and it is tried again on the next lookup.
	if prev == nil || prev.Latest != m.Latest || prev.LatestAt.IsZero() {
		var doc struct {
			Time map[string]string `json:"time"`
		}
		if err := c.getJSON(ctx, c.Base.Npm+"/"+name, &doc); err == nil {
			m.LatestAt = parseTime(doc.Time[m.Latest])
		} else if ctx.Err() != nil {
			return packages.Meta{}, ctx.Err()
		}
	}
	return m, nil
}

// CratesIndexPath is a crate's file in the sparse index.
func CratesIndexPath(name string) string {
	n := strings.ToLower(name)
	switch len(n) {
	case 1:
		return "1/" + n
	case 2:
		return "2/" + n
	case 3:
		return "3/" + n[:1] + "/" + n
	}
	return n[:2] + "/" + n[2:4] + "/" + n
}

type crateVersion struct {
	Vers   string `json:"vers"`
	Yanked bool   `json:"yanked"`
}

// latestCrate picks the newest unyanked stable version, falling back to the
// newest unyanked prerelease.
func latestCrate(vs []crateVersion) string {
	best, bestPre := "", ""
	for _, v := range vs {
		if v.Yanked {
			continue
		}
		slot := &best
		if packages.IsPrerelease(v.Vers) {
			slot = &bestPre
		}
		if c, ok := packages.CompareVersions("cargo", v.Vers, *slot); *slot == "" || (ok && c > 0) {
			*slot = v.Vers
		}
	}
	if best == "" {
		return bestPre
	}
	return best
}

type crateResp struct {
	Crate struct {
		Description string   `json:"description"`
		Homepage    string   `json:"homepage"`
		Repository  string   `json:"repository"`
		Keywords    []string `json:"keywords"`
	} `json:"crate"`
	Versions []struct {
		Num       string `json:"num"`
		CreatedAt string `json:"created_at"`
		License   string `json:"license"`
	} `json:"versions"`
}

func (c *Client) crates(ctx context.Context, p packages.Package, prev *packages.Meta, describe bool) (packages.Meta, bool, error) {
	body, err := c.get(ctx, c.Base.CratesIndex+"/"+CratesIndexPath(p.Name))
	if err != nil {
		return packages.Meta{}, false, notFound(err, "crates.io")
	}
	var vs []crateVersion
	for _, line := range strings.Split(string(body), "\n") {
		var v crateVersion
		if strings.TrimSpace(line) != "" && json.Unmarshal([]byte(line), &v) == nil {
			vs = append(vs, v)
		}
	}
	m := packages.Meta{Latest: latestCrate(vs)}
	for _, v := range vs {
		if v.Vers == p.Version {
			m.InstalledYanked = v.Yanked
		}
	}
	// The index has no dates or descriptions; the API has both but is rate
	// limited, so it is asked when the cache is old or a release appeared.
	if !describe && prev != nil && prev.Latest == m.Latest {
		return m, false, nil
	}
	var r crateResp
	if err := c.getJSON(ctx, c.Base.CratesAPI+"/api/v1/crates/"+url.PathEscape(p.Name), &r); err != nil {
		return m, false, notFound(err, "crates.io")
	}
	m.Description, m.Homepage, m.Keywords = oneLine(r.Crate.Description), r.Crate.Homepage, r.Crate.Keywords
	m.Repo = cleanRepo(r.Crate.Repository)
	for _, v := range r.Versions {
		if v.Num == m.Latest {
			m.LatestAt, m.License = parseTime(v.CreatedAt), v.License
		}
	}
	return m, true, nil
}

// goProxy returns the proxy to ask about mod, or an error saying why none
// applies (GOPROXY=direct/off, or the module is private).
func (c *Client) goProxy(mod string) (string, error) {
	get := func(k string) string {
		if c.Env == nil {
			return ""
		}
		return c.Env.Get(k)
	}
	for _, k := range []string{"GONOPROXY", "GOPRIVATE"} {
		if pat := get(k); pat != "" && module.MatchPrefixPatterns(pat, mod) {
			return "", fmt.Errorf("private module (%s); not looked up", k)
		}
	}
	if c.Base.GoProxy != "" {
		return c.Base.GoProxy, nil
	}
	list := get("GOPROXY")
	if list == "" {
		list = DefaultGoProxy
	}
	first := strings.FieldsFunc(list, func(r rune) bool { return r == ',' || r == '|' })
	if len(first) == 0 || first[0] == "direct" || first[0] == "off" {
		return "", fmt.Errorf("GOPROXY=%s has no proxy to ask", list)
	}
	return strings.TrimSuffix(first[0], "/"), nil
}

type goLatest struct {
	Version string `json:"Version"`
	Time    string `json:"Time"`
	Origin  struct {
		URL string `json:"URL"`
	} `json:"Origin"`
}

func (c *Client) goproxy(ctx context.Context, p packages.Package, describe bool) (packages.Meta, bool, error) {
	proxy, err := c.goProxy(p.Ident)
	if err != nil {
		return packages.Meta{}, false, err
	}
	esc, err := module.EscapePath(p.Ident)
	if err != nil {
		return packages.Meta{}, false, err
	}
	var r goLatest
	if err := c.getJSON(ctx, proxy+"/"+esc+"/@latest", &r); err != nil {
		return packages.Meta{}, false, notFound(err, "the Go module proxy")
	}
	m := packages.Meta{Latest: r.Version, LatestAt: parseTime(r.Time), Repo: cleanRepo(r.Origin.URL)}
	if m.Repo == "" {
		m.Repo = "https://" + p.Ident
	}
	if !describe {
		return m, false, nil
	}
	repo := githubRepo(m.Repo)
	if repo == "" {
		repo = githubRepo("https://" + p.Ident)
	}
	if repo == "" {
		// Only GitHub-hosted modules have descriptions to fetch.
		return m, true, nil
	}
	if err := c.describeGitHub(ctx, repo, &m); err != nil {
		return m, false, nil //nolint:nilerr // the version data is still good; descriptions are retried next time
	}
	return m, true, nil
}

// githubRepo extracts owner/repo from a github.com URL.
func githubRepo(u string) string {
	_, rest, ok := strings.Cut(u, "github.com/")
	if !ok {
		return ""
	}
	parts := strings.Split(rest, "/")
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return ""
	}
	return parts[0] + "/" + strings.TrimSuffix(parts[1], ".git")
}

type rubygemsResp struct {
	Version          string   `json:"version"`
	VersionCreatedAt string   `json:"version_created_at"`
	Info             string   `json:"info"`
	HomepageURI      string   `json:"homepage_uri"`
	SourceCodeURI    string   `json:"source_code_uri"`
	Licenses         []string `json:"licenses"`
}

func (c *Client) rubygems(ctx context.Context, p packages.Package) (packages.Meta, error) {
	var r rubygemsResp
	if err := c.getJSON(ctx, c.Base.Rubygems+"/api/v1/gems/"+url.PathEscape(p.Name)+".json", &r); err != nil {
		return packages.Meta{}, notFound(err, "rubygems.org")
	}
	m := packages.Meta{Latest: r.Version, LatestAt: parseTime(r.VersionCreatedAt), Description: oneLine(r.Info),
		Homepage: r.HomepageURI, Repo: cleanRepo(r.SourceCodeURI), License: strings.Join(r.Licenses, " OR ")}
	if m.Repo == "" && isForge(m.Homepage) {
		m.Repo = cleanRepo(m.Homepage)
	}
	return m, nil
}

type ghRepo struct {
	Description string `json:"description"`
	Homepage    string `json:"homepage"`
	HTMLURL     string `json:"html_url"`
	License     *struct {
		SPDX string `json:"spdx_id"`
	} `json:"license"`
	Topics   []string `json:"topics"`
	Archived bool     `json:"archived"`
}

func (c *Client) describeGitHub(ctx context.Context, repo string, m *packages.Meta) error {
	var r ghRepo
	if err := c.gh(ctx, "repos/"+repo, &r); err != nil {
		return notFound(err, "GitHub")
	}
	m.Description, m.Homepage, m.Keywords, m.Archived = oneLine(r.Description), r.Homepage, r.Topics, r.Archived
	if r.HTMLURL != "" {
		m.Repo = r.HTMLURL
	}
	if r.License != nil && r.License.SPDX != "NOASSERTION" {
		m.License = r.License.SPDX
	}
	return nil
}

type ghRelease struct {
	TagName     string `json:"tag_name"`
	PublishedAt string `json:"published_at"`
}

func (c *Client) github(ctx context.Context, p packages.Package, describe bool) (packages.Meta, bool, error) {
	m := packages.Meta{Repo: "https://github.com/" + p.Ident}
	var rel ghRelease
	switch err := c.gh(ctx, "repos/"+p.Ident+"/releases/latest", &rel); {
	case errors.Is(err, ErrNotFound):
		// Script extensions often have no releases; gh tracks a commit then
		// and there is no version to compare.
	case err != nil:
		return m, false, err
	default:
		m.Latest, m.LatestAt = rel.TagName, parseTime(rel.PublishedAt)
	}
	if !describe {
		return m, false, nil
	}
	if err := c.describeGitHub(ctx, p.Ident, &m); err != nil {
		return m, false, err
	}
	return m, true, nil
}

// GitHubUser asks gh for the signed-in user's login.
func GitHubUser(ctx context.Context, env *exec.Env) (string, error) {
	res := env.Run(ctx, "gh", []string{"api", "user", "--jq", ".login"}, exec.Options{Timeout: 15 * time.Second})
	if res.Code != 0 {
		msg, _, _ := strings.Cut(strings.TrimSpace(res.Stderr), "\n")
		return "", fmt.Errorf("gh api user: %s", msg)
	}
	return strings.TrimSpace(res.Stdout), nil
}
