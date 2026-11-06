package sysaudit

import (
	"bufio"
	"os"
	"strings"

	core "github.com/brezzkin-dev/CINT/internal/cyber/core"
)

func checkContainerDetect(r *core.Result) {
	if _, err := os.Stat("/.dockerenv"); err == nil {
		r.AddExtra("environment", "docker")
	}
	if _, err := os.Stat("/run/.containerenv"); err == nil {
		r.AddExtra("environment", "podman")
	}
	if _, err := os.Stat("/var/run/docker.sock"); err == nil {
		r.Add(core.Finding{
			Tool: "sysaudit", Severity: core.SevHigh,
			Title:  "Docker socket mounted",
			Detail: "/var/run/docker.sock — container escape risk",
		})
	}
	if b, err := os.ReadFile("/proc/1/cgroup"); err == nil {
		s := string(b)
		if strings.Contains(s, "docker") || strings.Contains(s, "kubepods") {
			r.AddExtra("cgroup", "containerized")
		}
	}
	if b, err := os.ReadFile("/proc/self/status"); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(line, "Seccomp:") {
				r.AddExtra("seccomp", strings.TrimSpace(line[len("Seccomp:"):]))
			}
		}
	}
}

func auditCapabilities(r *core.Result) {
	f, err := os.Open("/proc/self/status")
	if err != nil {
		return
	}
	defer f.Close()
	caps := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "CapInh:") ||
			strings.HasPrefix(line, "CapPrm:") ||
			strings.HasPrefix(line, "CapEff:") ||
			strings.HasPrefix(line, "CapBnd:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				caps[parts[0]] = strings.TrimSpace(parts[1])
			}
		}
	}
	r.AddExtra("capabilities", caps)

	eff, ok := caps["CapEff"]
	if !ok {
		return
	}
	dangerous := map[int]string{
		0:  "CAP_CHOWN",
		1:  "CAP_DAC_OVERRIDE",
		2:  "CAP_DAC_READ_SEARCH",
		7:  "CAP_SETUID",
		8:  "CAP_SETGID",
		12: "CAP_NET_ADMIN",
		13: "CAP_NET_RAW",
		16: "CAP_SYS_MODULE",
		17: "CAP_SYS_RAWIO",
		19: "CAP_SYS_PTRACE",
		21: "CAP_SYS_ADMIN",
		22: "CAP_SYS_BOOT",
		23: "CAP_SYS_NICE",
		27: "CAP_MKNOD",
	}
	var bits uint64
	for _, c := range strings.TrimSpace(eff) {
		bits <<= 4
		switch {
		case c >= '0' && c <= '9':
			bits |= uint64(c - '0')
		case c >= 'a' && c <= 'f':
			bits |= uint64(c-'a') + 10
		case c >= 'A' && c <= 'F':
			bits |= uint64(c-'A') + 10
		}
	}
	for bit, name := range dangerous {
		if bits&(1<<uint(bit)) != 0 {
			sev := core.SevMed
			if name == "CAP_SYS_ADMIN" || name == "CAP_SYS_MODULE" ||
				name == "CAP_SYS_PTRACE" || name == "CAP_SYS_RAWIO" {
				sev = core.SevHigh
			}
			r.Add(core.Finding{
				Tool: "sysaudit", Severity: sev,
				Title: "Elevated capability: " + name,
			})
		}
	}
}

func auditSudoers(r *core.Result) {
	paths := []string{"/etc/sudoers"}
	if entries, err := os.ReadDir("/etc/sudoers.d"); err == nil {
		for _, e := range entries {
			if !e.IsDir() {
				paths = append(paths, "/etc/sudoers.d/"+e.Name())
			}
		}
	}
	risky := []string{"NOPASSWD", "ALL=(ALL)", "!authenticate"}
	for _, p := range paths {
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			for _, pat := range risky {
				if strings.Contains(line, pat) {
					r.Add(core.Finding{
						Tool: "sysaudit", Severity: core.SevHigh,
						Title:  "Risky sudoers rule",
						Detail: p + ": " + line,
					})
					break
				}
			}
		}
		f.Close()
	}
}

func auditCron(r *core.Result) {
	paths := []string{"/etc/crontab"}
	for _, d := range []string{"/etc/cron.d", "/var/spool/cron", "/var/spool/cron/crontabs"} {
		if entries, err := os.ReadDir(d); err == nil {
			for _, e := range entries {
				paths = append(paths, d+"/"+e.Name())
			}
		}
	}
	suspicious := []string{"/tmp/", "curl ", "wget ", "bash -c", "| sh", "| bash"}
	for _, p := range paths {
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			for _, s := range suspicious {
				if strings.Contains(line, s) {
					r.Add(core.Finding{
						Tool: "sysaudit", Severity: core.SevHigh,
						Title:  "Suspicious cron entry",
						Detail: p + ": " + line,
					})
					break
				}
			}
		}
		f.Close()
	}
}
