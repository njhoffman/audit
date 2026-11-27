package containers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParseRef(t *testing.T) {
	for ref, want := range map[string]string{
		"alpine":                       "registry-1.docker.io library/alpine latest",
		"alpine:3.20":                  "registry-1.docker.io library/alpine 3.20",
		"docker.io/library/alpine:3":   "registry-1.docker.io library/alpine 3",
		"grafana/grafana:11":           "registry-1.docker.io grafana/grafana 11",
		"ghcr.io/astral-sh/uv:latest":  "ghcr.io astral-sh/uv latest",
		"quay.io/podman/stable":        "quay.io podman/stable latest",
		"localhost:5000/app:dev":       "localhost:5000 app dev",
		"registry.local:5000/a/b/c:v1": "registry.local:5000 a/b/c v1",
	} {
		h, r, tag := parseRef(ref)
		if got := h + " " + r + " " + tag; got != want {
			t.Errorf("%s: %q, want %q", ref, got, want)
		}
	}
}

func TestChallengeParams(t *testing.T) {
	p := challengeParams(`realm="https://auth.example/token",service="reg, one",scope="repository:a/b:pull" , bare=x`)
	if p["realm"] != "https://auth.example/token" || p["service"] != "reg, one" || p["scope"] != "repository:a/b:pull" || p["bare"] != "x" {
		t.Errorf("params %v", p)
	}
}

// registry is a TLS v2 registry wanting an anonymous bearer token, with
// app:v1 present, app:nodigest answering no digest and secret:v1 refused.
func registry(t *testing.T) (*httptest.Server, *[]string) {
	t.Helper()
	var methods []string
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		methods = append(methods, r.Method+" "+r.URL.Path)
		switch {
		case r.URL.Path == "/token":
			if r.URL.Query().Get("scope") == "repository:secret:pull" {
				http.Error(w, "denied", http.StatusUnauthorized)
				return
			}
			if r.URL.Query().Get("service") != "test-registry" || r.Header.Get("Authorization") != "" {
				http.Error(w, "bad token request", http.StatusBadRequest)
				return
			}
			_, _ = w.Write([]byte(`{"token":"anon"}`))
		case r.Header.Get("Authorization") != "Bearer anon":
			w.Header().Set("WWW-Authenticate", `Bearer realm="`+srv.URL+`/token",service="test-registry",scope="repository:`+strings.Split(strings.TrimPrefix(r.URL.Path, "/v2/"), "/manifests/")[0]+`:pull"`)
			w.WriteHeader(http.StatusUnauthorized)
		case r.Method != http.MethodHead || !strings.Contains(r.Header.Get("Accept"), "image.index"):
			http.Error(w, "HEAD with the index types only", http.StatusBadRequest)
		case r.URL.Path == "/v2/app/manifests/v1":
			w.Header().Set("Docker-Content-Digest", "sha256:abc")
		case r.URL.Path == "/v2/app/manifests/nodigest":
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &methods
}

func TestRegistryDigest(t *testing.T) {
	srv, methods := registry(t)
	r := &Registry{Client: srv.Client()}
	host := strings.TrimPrefix(srv.URL, "https://")
	ctx := context.Background()
	d, err := r.Digest(ctx, host+"/app:v1")
	if err != nil || d != "sha256:abc" {
		t.Fatalf("app:v1: %q %v", d, err)
	}
	for _, m := range *methods {
		if strings.HasPrefix(m, "GET /v2/") {
			t.Errorf("a manifest GET counts as a pull: %v", *methods)
		}
	}
	if _, err := r.Digest(ctx, host+"/app:nodigest"); !errors.Is(err, errNoDigest) {
		t.Errorf("no digest: %v", err)
	}
	if _, err := r.Digest(ctx, host+"/secret:v1"); !errors.Is(err, errNeedsAuth) {
		t.Errorf("refused token: %v", err)
	}
	if _, err := r.Digest(ctx, host+"/app:gone"); err == nil || !strings.Contains(err.Error(), "no such tag") {
		t.Errorf("missing tag: %v", err)
	}
}

func TestRegistryWantsBasicAuth(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("WWW-Authenticate", `Basic realm="private"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	r := &Registry{Client: srv.Client()}
	if _, err := r.Digest(context.Background(), strings.TrimPrefix(srv.URL, "https://")+"/app:v1"); !errors.Is(err, errNeedsAuth) {
		t.Errorf("basic auth: %v", err)
	}
}

func TestRegistryTokenRealmMustBeHTTPS(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="http://insecure.example/token"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	r := &Registry{Client: srv.Client()}
	if _, err := r.Digest(context.Background(), strings.TrimPrefix(srv.URL, "https://")+"/app:v1"); !errors.Is(err, errNeedsAuth) {
		t.Errorf("http realm: %v", err)
	}
}
