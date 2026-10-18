package programs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"

	"github.com/njhoffman/audit/internal/scan"
)

const dockerDaemonJSON = "/etc/docker/daemon.json"

// dockerDaemon mirrors the subset of fields we audit. Unknown fields are
// preserved via the catch-all map so the rule engine can inspect them.
type dockerDaemon struct {
	Hosts           []string        `json:"hosts"`
	TLS             *bool           `json:"tls,omitempty"`
	TLSVerify       *bool           `json:"tlsverify,omitempty"`
	ICC             *bool           `json:"icc,omitempty"`
	UserlandProxy   *bool           `json:"userland-proxy,omitempty"`
	LiveRestore     *bool           `json:"live-restore,omitempty"`
	NoNewPrivileges *bool           `json:"no-new-privileges,omitempty"`
	LogDriver       string          `json:"log-driver,omitempty"`
	LogOpts         json.RawMessage `json:"log-opts,omitempty"`
	UserNSRemap     string          `json:"userns-remap,omitempty"`
}

func analyzeDocker(_ context.Context) ProgramResult {
	out := ProgramResult{Program: ProgramDocker, Source: dockerDaemonJSON}

	data, err := os.ReadFile(dockerDaemonJSON) // #nosec G304 -- well-known config path
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			out.Skipped = true
			out.Reason = "no /etc/docker/daemon.json (engine running on defaults)"
			return out
		}
		out.Skipped = true
		out.Reason = err.Error()
		return out
	}
	var d dockerDaemon
	if err := json.Unmarshal(data, &d); err != nil {
		out.Findings = append(out.Findings, scan.Finding{
			Severity: scan.SeverityError,
			Subject:  "docker: daemon.json failed to parse",
			Detail:   err.Error() + " (source: " + dockerDaemonJSON + ")",
		})
		return out
	}
	out.Findings = append(out.Findings, dockerRules(d, data)...)
	out.Notes = append(out.Notes,
		"checks apply to explicit fields in daemon.json; engine defaults are not enforced",
	)
	return out
}

func dockerRules(d dockerDaemon, raw []byte) []scan.Finding {
	out := []scan.Finding{}

	// Any tcp:// host in the hosts list is a network-exposed daemon socket.
	// Without TLS verification this is effectively root-on-network.
	for _, h := range d.Hosts {
		if !strings.HasPrefix(h, "tcp://") {
			continue
		}
		tlsverify := d.TLSVerify != nil && *d.TLSVerify
		tls := d.TLS != nil && *d.TLS
		if !tlsverify {
			detail := fmt.Sprintf("hosts entry %q exposes the docker socket without tlsverify=true.", h)
			if !tls {
				detail += " tls is also not enabled."
			}
			out = append(out, scan.Finding{
				Severity: scan.SeverityCritical,
				Subject:  "docker: tcp host without tlsverify",
				Detail:   detail + " Anyone reaching this socket has root on the host. Source: " + dockerDaemonJSON,
			})
		}
	}

	// Inter-container communication: default true. Some hardening guides
	// recommend false to require explicit network policy.
	if d.ICC == nil || *d.ICC {
		// Only fire if explicitly set to true (or absent? omit absent —
		// we don't enforce defaults).
		if d.ICC != nil && *d.ICC {
			out = append(out, scan.Finding{
				Severity: scan.SeverityNotice,
				Subject:  "docker: icc=true (explicit)",
				Detail:   "Inter-container communication on the default bridge is unrestricted. Set icc=false for stricter isolation if not needed.",
			})
		}
	}

	if d.LiveRestore != nil && !*d.LiveRestore {
		out = append(out, scan.Finding{
			Severity: scan.SeverityNotice,
			Subject:  "docker: live-restore=false",
			Detail:   "Containers will be stopped on dockerd restart. Enabling live-restore avoids that.",
		})
	}

	if d.NoNewPrivileges != nil && !*d.NoNewPrivileges {
		out = append(out, scan.Finding{
			Severity: scan.SeverityNotice,
			Subject:  "docker: no-new-privileges=false",
			Detail:   "Container processes can gain new privileges via setuid binaries; consider enabling no-new-privileges by default.",
		})
	}

	// log-driver json-file without a max-size lets logs fill the disk.
	if strings.EqualFold(d.LogDriver, "json-file") || (d.LogDriver == "" && len(d.LogOpts) > 0) {
		opts := map[string]string{}
		_ = json.Unmarshal(d.LogOpts, &opts)
		if _, ok := opts["max-size"]; !ok {
			out = append(out, scan.Finding{
				Severity: scan.SeverityNotice,
				Subject:  "docker: json-file log-driver without max-size",
				Detail:   "Container logs are unbounded; set log-opts.max-size and max-file to cap disk usage.",
			})
		}
	}

	return out
}
