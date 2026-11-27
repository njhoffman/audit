package containers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Lookup answers the digest a registry's tag names now.
type Lookup func(ctx context.Context, ref string) (string, error)

// errNeedsAuth is a registry refusing an anonymous lookup: a private
// image, which the tools with the engine's credentials can still ask.
var errNeedsAuth = errors.New("the registry wants a login")

// errNoDigest is a registry answering without a Docker-Content-Digest.
var errNoDigest = errors.New("the registry sent no digest")

// manifestTypes are the manifests a HEAD accepts, an index or manifest
// list first: that is the digest a pull of a multi-platform image records.
var manifestTypes = strings.Join([]string{
	"application/vnd.oci.image.index.v1+json",
	"application/vnd.docker.distribution.manifest.list.v2+json",
	"application/vnd.oci.image.manifest.v1+json",
	"application/vnd.docker.distribution.manifest.v2+json",
}, ", ")

// Registry asks registries over their v2 API with a HEAD of the tag's
// manifest. Docker Hub does not count a HEAD against its pull rate limit,
// where a GET of the manifest (and of every platform's, as docker buildx
// imagetools inspect does) counts one pull each. Only anonymous tokens are
// fetched; a registry that wants a login answers errNeedsAuth.
type Registry struct {
	// Client defaults to one with a 20s timeout.
	Client *http.Client
}

// Digest is the Lookup of r.
func (r *Registry) Digest(ctx context.Context, ref string) (string, error) {
	host, repo, tag := parseRef(ref)
	c := r.Client
	if c == nil {
		c = &http.Client{Timeout: 20 * time.Second}
	}
	u := "https://" + host + "/v2/" + repo + "/manifests/" + url.PathEscape(tag)
	resp, err := head(ctx, c, u, "")
	if err != nil {
		return "", err
	}
	if resp.StatusCode == http.StatusUnauthorized {
		challenge := resp.Header.Get("WWW-Authenticate")
		token, err := anonymousToken(ctx, c, challenge, repo)
		if err != nil {
			return "", err
		}
		if resp, err = head(ctx, c, u, token); err != nil {
			return "", err
		}
	}
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusUnauthorized, http.StatusForbidden:
		return "", errNeedsAuth
	case http.StatusNotFound:
		return "", errors.New("the registry has no such tag")
	default:
		return "", fmt.Errorf("the registry answered %s", resp.Status)
	}
	d := resp.Header.Get("Docker-Content-Digest")
	if d == "" {
		return "", errNoDigest
	}
	return digestOrErr(d)
}

func head(ctx context.Context, c *http.Client, u, token string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", manifestTypes)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	_ = resp.Body.Close()
	return resp, nil
}

// anonymousToken fetches a pull token from the realm of a Bearer
// challenge, without credentials. Basic and other schemes need a login.
func anonymousToken(ctx context.Context, c *http.Client, challenge, repo string) (string, error) {
	scheme, params, _ := strings.Cut(challenge, " ")
	if !strings.EqualFold(scheme, "Bearer") {
		return "", errNeedsAuth
	}
	p := challengeParams(params)
	realm, err := url.Parse(p["realm"])
	if err != nil || realm.Scheme != "https" {
		return "", errNeedsAuth
	}
	q := realm.Query()
	if s := p["service"]; s != "" {
		q.Set("service", s)
	}
	scope := p["scope"]
	if scope == "" {
		scope = "repository:" + repo + ":pull"
	}
	q.Set("scope", scope)
	realm.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, realm.String(), nil)
	if err != nil {
		return "", err
	}
	resp, err := c.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", errNeedsAuth
	}
	var t struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&t); err != nil {
		return "", fmt.Errorf("read the registry token: %w", err)
	}
	if t.Token == "" {
		t.Token = t.AccessToken
	}
	if t.Token == "" {
		return "", errNeedsAuth
	}
	return t.Token, nil
}

// challengeParams splits `realm="...",service="...",scope="..."`.
func challengeParams(s string) map[string]string {
	out := map[string]string{}
	for s != "" {
		s = strings.TrimLeft(s, ", ")
		k, rest, ok := strings.Cut(s, "=")
		if !ok {
			break
		}
		var v string
		if strings.HasPrefix(rest, `"`) {
			end := strings.Index(rest[1:], `"`)
			if end < 0 {
				v, s = rest[1:], ""
			} else {
				v, s = rest[1:end+1], rest[end+2:]
			}
		} else {
			v, s, _ = strings.Cut(rest, ",")
		}
		out[strings.ToLower(strings.TrimSpace(k))] = v
	}
	return out
}

// parseRef splits an image reference the way docker resolves it: a first
// component with a dot, a colon or "localhost" is the registry, else Docker
// Hub, where a one-component name lives under library/.
func parseRef(ref string) (host, repo, tag string) {
	name := ref
	tag = "latest"
	if i := strings.LastIndex(ref, ":"); i > strings.LastIndex(ref, "/") {
		name, tag = ref[:i], ref[i+1:]
	}
	host = "docker.io"
	if first, rest, ok := strings.Cut(name, "/"); ok && (strings.ContainsAny(first, ".:") || first == "localhost") {
		host, name = first, rest
	}
	if host == "docker.io" || host == "index.docker.io" {
		host = "registry-1.docker.io"
		if !strings.Contains(name, "/") {
			name = "library/" + name
		}
	}
	return host, name, tag
}
