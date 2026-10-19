// Package security checks the workstation's exposure: whether a firewall
// service runs, which TCP ports listen beyond loopback (and risky UDP
// ones), the permissions and passphrases of ~/.ssh, world-writable
// directories and files on PATH, and clock synchronization.
package security

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/njhoffman/audit/internal/exec"
	"github.com/njhoffman/audit/internal/scan"
)

// Options configures the scan.
type Options struct {
	Env *exec.Env
	// Home is where ~/.ssh lives.
	Home string
	// Path is the PATH checked for world-writable entries.
	Path []string
}

// riskyPorts are services that should not face a network unless meant to.
var riskyPorts = map[int]string{21: "ftp", 23: "telnet", 69: "tftp", 111: "rpcbind", 137: "netbios", 139: "smb", 161: "snmp",
	445: "smb", 2049: "nfs", 2375: "docker (no TLS)", 3306: "mysql", 5432: "postgres", 5900: "vnc", 6379: "redis",
	9200: "elasticsearch", 11211: "memcached", 27017: "mongodb"}

// Listener is one socket open beyond loopback.
type Listener struct {
	Proto   string `json:"proto"`
	Addr    string `json:"addr"`
	Port    int    `json:"port"`
	Process string `json:"process,omitempty"`
}

var procRe = regexp.MustCompile(`\(\("([^"]+)"`)

// ParseSS reads `ss -Htulnp`: TCP listeners and UDP sockets bound beyond
// loopback. Multicast and link-local addresses are left out.
func ParseSS(out string) []Listener {
	var ls []Listener
	seen := map[string]bool{}
	for line := range strings.SplitSeq(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 5 || (f[0] == "tcp" && f[1] != "LISTEN") || (f[0] != "tcp" && f[0] != "udp") {
			continue
		}
		local := f[4]
		i := strings.LastIndexByte(local, ':')
		if i < 0 {
			continue
		}
		host := strings.Trim(strings.SplitN(local[:i], "%", 2)[0], "[]")
		port, err := strconv.Atoi(local[i+1:])
		if err != nil {
			continue
		}
		if ip := net.ParseIP(host); ip != nil && (ip.IsLoopback() || ip.IsMulticast() || ip.IsLinkLocalUnicast()) {
			continue
		}
		if host == "localhost" {
			continue
		}
		l := Listener{Proto: f[0], Addr: host, Port: port}
		if m := procRe.FindStringSubmatch(line); m != nil {
			l.Process = m[1]
		}
		key := fmt.Sprintf("%s/%d", l.Proto, l.Port)
		if seen[key] {
			continue
		}
		seen[key] = true
		ls = append(ls, l)
	}
	sort.Slice(ls, func(i, j int) bool { return ls[i].Proto+fmt.Sprint(ls[i].Port) < ls[j].Proto+fmt.Sprint(ls[j].Port) })
	return ls
}

// Scan implements the system part.
func Scan(ctx context.Context, o Options) (*scan.Result, error) {
	started := time.Now()
	var fs []scan.Finding
	summary := map[string]any{}
	add := func(check string, sev scan.Severity, subject, detail string) {
		fs = append(fs, scan.Finding{Check: check, Severity: sev, Subject: subject, Detail: detail})
	}
	run := func(name string, args ...string) exec.Result {
		if o.Env == nil {
			return exec.Result{Code: exec.ExitNotFound}
		}
		return o.Env.Run(ctx, name, args, exec.Options{Timeout: 15 * time.Second})
	}

	fw := []string{"ufw", "firewalld", "nftables"}
	if r := run("systemctl", append([]string{"is-active"}, fw...)...); r.Code != exec.ExitNotFound {
		active := ""
		for i, st := range strings.Fields(r.Stdout) {
			if st == "active" && i < len(fw) {
				active = fw[i]
				break
			}
		}
		summary["firewall"] = active
		if active == "" {
			add("firewall", scan.SeverityNotice, "firewall", "no firewall service (ufw, firewalld, nftables) is active")
		}
	}

	if r := run("ss", "-Htulnp"); r.OK() {
		ls := ParseSS(r.Stdout)
		summary["exposed_ports"] = len(ls)
		for _, l := range ls {
			who := l.Process
			if who == "" {
				who = "another user's process"
			}
			subject := fmt.Sprintf("%s/%d", l.Proto, l.Port)
			if svc, risky := riskyPorts[l.Port]; risky {
				add("exposed_port", scan.SeverityWarning, subject,
					fmt.Sprintf("%s (%s) listens on %s port %d (%s); bind it to 127.0.0.1 or firewall it", svc, who, l.Addr, l.Port, l.Proto))
			} else if l.Proto == "tcp" {
				add("listening", scan.SeverityInfo, subject, fmt.Sprintf("%s listens on %s:%d", who, l.Addr, l.Port))
			}
		}
	}

	fs = append(fs, sshPerms(ctx, o)...)
	fs = append(fs, writablePath(o.Path)...)

	if r := run("timedatectl", "show", "-p", "NTP", "-p", "NTPSynchronized"); r.OK() {
		props := map[string]string{}
		for line := range strings.SplitSeq(r.Stdout, "\n") {
			if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok {
				props[k] = v
			}
		}
		summary["ntp_synchronized"] = props["NTPSynchronized"] == "yes"
		switch {
		case props["NTP"] == "no":
			add("time_sync", scan.SeverityNotice, "clock", "network time sync is off; timedatectl set-ntp true")
		case props["NTPSynchronized"] == "no":
			add("time_sync", scan.SeverityWarning, "clock", "the clock is not synchronized; check systemd-timesyncd or chrony")
		}
	}
	return &scan.Result{Kind: "security", StartedAt: started, FinishedAt: time.Now(), Summary: summary, Findings: fs}, nil
}

func readHead(p string, n int) string {
	f, err := os.Open(p) // #nosec G304 -- files under ~/.ssh
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()
	b := make([]byte, n)
	m, _ := f.Read(b)
	return string(b[:m])
}

// sshPerms checks ~/.ssh: the directory and private keys private, config
// and authorized_keys not writable by others, and keys with a passphrase.
func sshPerms(ctx context.Context, o Options) []scan.Finding {
	dir := filepath.Join(o.Home, ".ssh")
	st, err := os.Stat(dir)
	if err != nil {
		return nil
	}
	var out []scan.Finding
	if st.Mode().Perm()&0o077 != 0 {
		out = append(out, scan.Finding{Check: "ssh_perms", Severity: scan.SeverityWarning, Subject: dir,
			Detail: fmt.Sprintf("%s is mode %04o; chmod 700 it", dir, st.Mode().Perm())})
	}
	es, _ := os.ReadDir(dir)
	for _, e := range es {
		p := filepath.Join(dir, e.Name())
		info, err := os.Lstat(p)
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		mode := info.Mode().Perm()
		switch {
		case strings.Contains(readHead(p, 64), "PRIVATE KEY"):
			if mode&0o077 != 0 {
				out = append(out, scan.Finding{Check: "ssh_perms", Severity: scan.SeverityError, Subject: p,
					Detail: fmt.Sprintf("private key %s is mode %04o; ssh refuses it, chmod 600 it", p, mode)})
			}
			if o.Env != nil && o.Env.Which("ssh-keygen") != "" {
				r := o.Env.Run(ctx, "ssh-keygen", []string{"-y", "-P", "", "-f", p}, exec.Options{Timeout: 10 * time.Second})
				if r.OK() {
					out = append(out, scan.Finding{Check: "ssh_passphrase", Severity: scan.SeverityNotice, Subject: p,
						Detail: p + " has no passphrase; anyone who copies it can use it (ssh-keygen -p -f " + p + ")"})
				}
			}
		case e.Name() == "authorized_keys" || e.Name() == "config":
			if mode&0o022 != 0 {
				out = append(out, scan.Finding{Check: "ssh_perms", Severity: scan.SeverityWarning, Subject: p,
					Detail: fmt.Sprintf("%s is writable by others (mode %04o); chmod 600 it", p, mode)})
			}
		}
	}
	return out
}

// writablePath reports world-writable PATH directories without the sticky
// bit, and world-writable files in PATH directories.
func writablePath(path []string) []scan.Finding {
	var out []scan.Finding
	seen := map[string]bool{}
	for _, d := range path {
		if d == "" || seen[d] {
			continue
		}
		seen[d] = true
		st, err := os.Stat(d)
		if err != nil || !st.IsDir() {
			continue
		}
		if st.Mode().Perm()&0o002 != 0 && st.Mode()&os.ModeSticky == 0 {
			out = append(out, scan.Finding{Check: "writable_path", Severity: scan.SeverityError, Subject: d,
				Detail: d + " is on PATH and writable by every user, who can plant commands there"})
		}
		es, _ := os.ReadDir(d)
		var files []string
		for _, e := range es {
			if info, err := os.Lstat(filepath.Join(d, e.Name())); err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0o002 != 0 {
				files = append(files, e.Name())
			}
		}
		if len(files) > 0 {
			sort.Strings(files)
			out = append(out, scan.Finding{Check: "writable_path", Severity: scan.SeverityWarning, Subject: d,
				Detail: fmt.Sprintf("world-writable files on PATH in %s: %s", d, strings.Join(files, ", "))})
		}
	}
	return out
}
