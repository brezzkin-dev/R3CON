package sysaudit

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	core "github.com/brezzkin-dev/CINT/internal/cyber/core"
)

func findSetuid(r *core.Result, root string) {
	filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		m := info.Mode()
		if m&os.ModeSetuid != 0 {
			r.Add(core.Finding{Tool: "sysaudit", Severity: core.SevHigh,
				Title: "SUID binary", Detail: p,
				Evidence: map[string]any{"mode": m.String()}})
		}
		if m&os.ModeSetgid != 0 {
			r.Add(core.Finding{Tool: "sysaudit", Severity: core.SevMed,
				Title: "SGID binary", Detail: p})
		}
		if m.Perm()&0002 != 0 {
			r.Add(core.Finding{Tool: "sysaudit", Severity: core.SevMed,
				Title: "world-writable", Detail: p})
		}
		return nil
	})
}

func auditPasswd(r *core.Result) {
	f, err := os.Open("/etc/passwd")
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		parts := strings.Split(sc.Text(), ":")
		if len(parts) < 7 {
			continue
		}
		uid, _ := strconv.Atoi(parts[2])
		if uid == 0 && parts[0] != "root" {
			r.Add(core.Finding{Tool: "sysaudit", Severity: core.SevCrit,
				Title: "Non-root UID 0", Detail: parts[0]})
		}
	}
}

func auditShadow(r *core.Result) {
	f, err := os.Open("/etc/shadow")
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		parts := strings.Split(sc.Text(), ":")
		if len(parts) < 2 {
			continue
		}
		if parts[1] == "" {
			r.Add(core.Finding{Tool: "sysaudit", Severity: core.SevCrit,
				Title: "Empty password", Detail: parts[0]})
		}
		if strings.HasPrefix(parts[1], "!") || strings.HasPrefix(parts[1], "*") {
			continue
		}
		if len(parts[1]) < 13 {
			r.Add(core.Finding{Tool: "sysaudit", Severity: core.SevMed,
				Title: "Weak hash scheme", Detail: parts[0]})
		}
	}
}

func auditSSH(r *core.Result) {
	f, err := os.Open("/etc/ssh/sshd_config")
	if err != nil {
		return
	}
	defer f.Close()
	checks := map[string]struct {
		Want string
		Sev  core.Severity
	}{
		"PermitRootLogin":        {"no", core.SevHigh},
		"PasswordAuthentication": {"no", core.SevMed},
		"PermitEmptyPasswords":   {"no", core.SevCrit},
		"X11Forwarding":          {"no", core.SevLow},
	}
	found := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			found[fields[0]] = fields[1]
		}
	}
	for k, cfg := range checks {
		v, ok := found[k]
		if !ok || v != cfg.Want {
			r.Add(core.Finding{Tool: "sysaudit", Severity: cfg.Sev,
				Title: "SSH: " + k + " = " + v, Detail: "should be " + cfg.Want})
		}
	}
}

func auditSysctl(r *core.Result) {
	checks := []struct {
		Path string
		Want string
		Sev  core.Severity
	}{
		{"/proc/sys/kernel/randomize_va_space", "2", core.SevHigh},
		{"/proc/sys/net/ipv4/ip_forward", "0", core.SevMed},
		{"/proc/sys/kernel/dmesg_restrict", "1", core.SevLow},
		{"/proc/sys/kernel/kptr_restrict", "1", core.SevLow},
	}
	for _, c := range checks {
		b, err := os.ReadFile(c.Path)
		if err != nil {
			continue
		}
		if strings.TrimSpace(string(b)) != c.Want {
			r.Add(core.Finding{Tool: "sysaudit", Severity: c.Sev,
				Title:    "sysctl: " + filepath.Base(c.Path),
				Evidence: map[string]any{"got": strings.TrimSpace(string(b)), "want": c.Want}})
		}
	}
}

func Audit(root string) *core.Result {
	r := core.NewResult("sysaudit", root)
	findSetuid(r, root)
	auditPasswd(r)
	auditShadow(r)
	auditSSH(r)
	auditSysctl(r)
	checkContainerDetect(r)
	auditCapabilities(r)
	auditSudoers(r)
	auditCron(r)
	r.Finish()
	return r
}
