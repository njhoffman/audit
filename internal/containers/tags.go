package containers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/njhoffman/audit/internal/exec"
)

// CheckBehind reports images whose tag the registry now points at a newer
// image.
const CheckBehind = "containers.image_behind"

// TagCheck is the registry check of one engine's tagged images.
type TagCheck struct {
	// Tool asked the registries: skopeo, or docker buildx.
	Tool    string `json:"tool,omitempty"`
	Checked int    `json:"checked"`
	// Behind are the images whose tag moved on.
	Behind []Behind `json:"behind,omitempty"`
	// Failed are the lookups that did not answer: ref and why.
	Failed []string `json:"failed,omitempty"`
	// Error says why nothing was checked.
	Error string `json:"error,omitempty"`
}

// Behind is one image a newer one replaced under its tag.
type Behind struct {
	Ref    string `json:"ref"`
	ID     string `json:"id"`
	Remote string `json:"remote"`
}

var errNoInspector = errors.New("needs skopeo, or docker buildx for docker images, to ask the registries")

// checkTags compares each tagged image pulled from a registry with what its
// tag names there now: the image is behind when none of its repo digests
// is the registry's digest for the tag. Images built here (no repo digest)
// and localhost ones are left out.
func checkTags(ctx context.Context, env *exec.Env, engine string) TagCheck {
	var t TagCheck
	inspect, tool := registryDigest(env, engine)
	if inspect == nil {
		t.Error = errNoInspector.Error()
		return t
	}
	t.Tool = tool
	out, err := run1(ctx, env, engine, "images", "--format", "{{.Repository}}\t{{.Tag}}\t{{.ID}}")
	if err != nil {
		t.Error = err.Error()
		return t
	}
	seen := map[string]bool{}
	for _, l := range lines(out) {
		f := strings.Split(l, "\t")
		if len(f) < 3 || f[0] == "<none>" || f[1] == "<none>" || strings.HasPrefix(f[0], "localhost/") {
			continue
		}
		ref := f[0] + ":" + f[1]
		if seen[ref] {
			continue
		}
		seen[ref] = true
		local := repoDigests(ctx, env, engine, f[2])
		if len(local) == 0 {
			continue
		}
		if err := ctx.Err(); err != nil {
			t.Error = err.Error()
			return t
		}
		remote, err := inspect(ctx, ref)
		if err != nil {
			t.Failed = append(t.Failed, ref+": "+err.Error())
			continue
		}
		t.Checked++
		if !slices.Contains(local, remote) {
			t.Behind = append(t.Behind, Behind{Ref: ref, ID: f[2], Remote: remote})
		}
	}
	return t
}

// repoDigests are the sha256 digests an image was pulled as.
func repoDigests(ctx context.Context, env *exec.Env, engine, id string) []string {
	out, err := run1(ctx, env, engine, "image", "inspect", "--format", "{{json .RepoDigests}}", id)
	if err != nil {
		return nil
	}
	var ds []string
	if json.Unmarshal([]byte(strings.TrimSpace(out)), &ds) != nil {
		return nil
	}
	var digests []string
	for _, d := range ds {
		if _, sum, ok := strings.Cut(d, "@"); ok {
			digests = append(digests, sum)
		}
	}
	return digests
}

// registryDigest picks how to ask a registry for the digest a tag names
// now (the top-level manifest's, a manifest list for multi-platform
// images, which is what a pull records): skopeo when installed, else
// docker buildx for docker. nil when neither applies.
func registryDigest(env *exec.Env, engine string) (func(context.Context, string) (string, error), string) {
	switch {
	case env.Which("skopeo") != "":
		return func(ctx context.Context, ref string) (string, error) {
			out, err := run1(ctx, env, "skopeo", "inspect", "--format", "{{.Digest}}", "docker://"+ref)
			if err != nil {
				return "", err
			}
			return digestOrErr(strings.TrimSpace(out))
		}, "skopeo"
	case engine == "docker":
		return func(ctx context.Context, ref string) (string, error) {
			out, err := run1(ctx, env, "docker", "buildx", "imagetools", "inspect", "--format", "{{json .Manifest}}", ref)
			if err != nil {
				return "", err
			}
			var m struct{ Digest string }
			if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &m); err != nil {
				return "", fmt.Errorf("read the manifest: %w", err)
			}
			return digestOrErr(m.Digest)
		}, "docker buildx"
	}
	return nil, ""
}

func digestOrErr(d string) (string, error) {
	if !strings.HasPrefix(d, "sha256:") {
		return "", fmt.Errorf("no digest in the answer (%q)", d)
	}
	return d, nil
}
