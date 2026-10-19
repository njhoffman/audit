# audit task runner. `just` lists the recipes.

set shell := ["bash", "-euo", "pipefail", "-c"]

# Build with the installed Go instead of downloading the go.mod toolchain.
export GOTOOLCHAIN := env("GOTOOLCHAIN", "local")

binary := "audit"
pkg := "github.com/njhoffman/audit"
bin_dir := "bin"
version := `git describe --tags --always --dirty 2>/dev/null || echo dev`
commit := `git rev-parse --short HEAD 2>/dev/null || echo unknown`
date := `date -u +%Y-%m-%dT%H:%M:%SZ`
ldflags := "-s -w -X " + pkg + "/internal/version.Version=" + version + " -X " + pkg + "/internal/version.Commit=" + commit + " -X " + pkg + "/internal/version.Date=" + date

# Pinned go-md2man version. Bump deliberately; reproducible builds matter
# more here than chasing latest.
md2man_version := "v2.0.4"

test_flags := "-race -count=1"

# List the recipes.
default:
    @just --list --unsorted

# Lint, test and build: the pre-commit gate.
check: fmt-check lint test build

# Cut a release after the gate passes: bump from CHANGELOG (or patch|minor|major),
# date the Unreleased section, commit, tag vX.Y.Z and push main with the tag.
# Flags: -n dry run, --no-push, --allow-major (leave 0.x).
release *args: check
    go run ./tools/release {{ args }}
    @# Rebuild the installed binary from the new tag (a dry run changes nothing).
    @if ! printf '%s\n' {{ args }} | grep -qx -- -n; then just install && echo "installed $(command -v audit || echo "$(go env GOPATH)/bin/audit")"; fi

# Build bin/audit.
build:
    mkdir -p {{ bin_dir }}
    go build -trimpath -ldflags '{{ ldflags }}' -o {{ bin_dir }}/{{ binary }} ./cmd/{{ binary }}

# Build, then run audit with the given arguments.
run *args: build
    ./{{ bin_dir }}/{{ binary }} {{ args }}

# go install the binary.
install:
    go install -trimpath -ldflags '{{ ldflags }}' ./cmd/{{ binary }}

# Run the tests. runner: go, gotestsum, gotestfmt or tparse.
test runner="go" pkgs="./...":
    #!/usr/bin/env bash
    set -euo pipefail
    case "{{ runner }}" in
      go)        go test {{ test_flags }} {{ pkgs }} ;;
      gotestsum) gotestsum --format pkgname -- {{ test_flags }} {{ pkgs }} ;;
      gotestfmt) go test -json {{ test_flags }} {{ pkgs }} | gotestfmt ;;
      tparse)    go test -json {{ test_flags }} {{ pkgs }} | tparse -all ;;
      *) echo "unknown runner '{{ runner }}' (want go, gotestsum, gotestfmt or tparse)" >&2; exit 2 ;;
    esac

# Run one test verbosely: just test-one ./internal/config TestLoad
test-one pkg name:
    go test {{ test_flags }} -run '^{{ name }}$' -v {{ pkg }}

# Write coverage.html.
cover:
    go test -coverprofile=coverage.out ./...
    go tool cover -html=coverage.out -o coverage.html
    @echo "coverage report: coverage.html"

# Run golangci-lint.
lint:
    golangci-lint run

# Run go vet.
vet:
    go vet ./...

# Format the sources.
fmt:
    gofmt -s -w .

# Fail if any file needs gofmt.
fmt-check:
    #!/usr/bin/env bash
    set -euo pipefail
    out=$(gofmt -s -l .)
    if [ -n "$out" ]; then
      echo "files need gofmt -s -w:" >&2
      echo "$out" >&2
      exit 1
    fi

# Render man/audit.1 from man/audit.1.md.
manpage:
    go run github.com/cpuguy83/go-md2man/v2@{{ md2man_version }} -in man/audit.1.md -out man/audit.1
    @echo "wrote man/audit.1 (preview: man -l man/audit.1)"

# Remove build artifacts.
clean:
    rm -rf {{ bin_dir }} coverage.out coverage.html

# List the development tools the recipes use.
tools:
    @echo "Required tools (install with: go install ...):"
    @echo "  github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest"
    @echo "  gotest.tools/gotestsum@latest"
    @echo "  github.com/gotesttools/gotestfmt/v2/cmd/gotestfmt@latest"
    @echo "  github.com/mfridman/tparse@latest"
    @echo "and just: https://just.systems"
