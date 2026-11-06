package dfir

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	core "github.com/brezzkin-dev/CINT/internal/cyber/core"
)

type Event struct {
	TS   time.Time `json:"ts"`
	Kind string    `json:"kind"`
	User string    `json:"user,omitempty"`
	Src  string    `json:"src,omitempty"`
	Info string    `json:"info"`
}

var (
	reAuth   = regexp.MustCompile(`^(\w{3}\s+\d+\s+\d+:\d+:\d+)\s+\S+\s+sshd\[\d+\]:\s+(\S+)\s+(.+)$`)
	reIP     = regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b`)
	reURL    = regexp.MustCompile(`https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{4,}`)
	reDomain = regexp.MustCompile(`\b([a-z0-9-]+\.)+[a-z]{2,}\b`)
	reHash   = regexp.MustCompile(`\b[a-fA-F0-9]{32,64}\b`)
)

func parseAuthLog(path string, r *core.Result, events *[]Event) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	year := time.Now().Year()
	for sc.Scan() {
		line := sc.Text()
		m := reAuth.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		ts, err := time.Parse("Jan 2 15:04:05 2006", fmt.Sprintf("%s %d", m[1], year))
		if err != nil {
			continue
		}
		kind := "auth"
		sev := core.SevInfo
		if strings.Contains(m[3], "Failed password") {
			kind, sev = "auth-fail", core.SevMed
		} else if strings.Contains(m[3], "Accepted") {
			kind = "auth-ok"
		} else if strings.Contains(m[3], "Invalid user") {
			kind, sev = "auth-invalid", core.SevHigh
		}
		*events = append(*events, Event{TS: ts, Kind: kind, Src: m[2], Info: m[3]})
		if sev.Rank() >= core.SevHigh.Rank() {
			r.Add(core.Finding{Tool: "dfir", Severity: sev,
				Title:    "Suspicious auth event",
				Detail:   line,
				Evidence: map[string]any{"ts": ts.Format(time.RFC3339)}})
		}
	}
}

func parseHistory(home string, r *core.Result, events *[]Event) {
	names := []string{".bash_history", ".zsh_history", ".sh_history", ".python_history", ".mysql_history"}
	patterns := map[string]string{
		"wget": "download", "curl": "download", "ssh": "remote",
		"nc ": "netcat", "ncat": "netcat", "chmod +x": "chmod",
		"base64 -d": "decode", "python -c": "inline", "perl -e": "inline",
		"rm -rf": "destructive", "scp ": "upload",
	}
	for _, name := range names {
		p := filepath.Join(home, name)
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
			for pat, kind := range patterns {
				if strings.Contains(line, pat) {
					*events = append(*events, Event{TS: time.Now().UTC(),
						Kind: "cmd-" + kind, User: filepath.Base(home), Info: line})
					break
				}
			}
			for _, ip := range reIP.FindAllString(line, -1) {
				r.Add(core.Finding{Tool: "dfir", Severity: core.SevLow,
					Title:    "IOC ip in history",
					Detail:   ip,
					Evidence: map[string]any{"source": p}})
			}
			for _, u := range reURL.FindAllString(line, -1) {
				r.Add(core.Finding{Tool: "dfir", Severity: core.SevMed,
					Title:    "IOC url in history",
					Detail:   u,
					Evidence: map[string]any{"source": p}})
			}
		}
		f.Close()
	}
}

func parseCron(r *core.Result, events *[]Event) {
	paths := []string{"/etc/crontab"}
	for _, d := range []string{"/etc/cron.d", "/var/spool/cron/crontabs"} {
		if entries, err := os.ReadDir(d); err == nil {
			for _, e := range entries {
				paths = append(paths, filepath.Join(d, e.Name()))
			}
		}
	}
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
			*events = append(*events, Event{TS: time.Now().UTC(), Kind: "cron",
				Info: p + ": " + line})
			if strings.Contains(line, "wget") || strings.Contains(line, "curl") ||
				strings.Contains(line, "base64") {
				r.Add(core.Finding{Tool: "dfir", Severity: core.SevHigh,
					Title: "Suspicious cron entry", Detail: p + ": " + line})
			}
		}
		f.Close()
	}
}

func parseWtmp(path string, r *core.Result, events *[]Event) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	const recSize = 384
	buf := make([]byte, recSize)
	for {
		_, err := io.ReadFull(f, buf)
		if err != nil {
			break
		}
		utType := int16(binary.LittleEndian.Uint16(buf[0:2]))
		ts := int32(binary.LittleEndian.Uint32(buf[340:344]))
		user := cstr(buf[44:76])
		line := cstr(buf[8:40])
		host := cstr(buf[76:332])
		if ts <= 0 {
			continue
		}
		kind := "wtmp"
		switch utType {
		case 7:
			kind = "login"
		case 8:
			kind = "logout"
		}
		*events = append(*events, Event{TS: time.Unix(int64(ts), 0).UTC(),
			Kind: kind, User: user, Src: host, Info: "tty=" + line})
	}
}

func cstr(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

func Investigate(root string) (*core.Result, error) {
	r := core.NewResult("dfir", root)
	var events []Event

	for _, hp := range []string{"/root", "/home"} {
		if hp == "/home" {
			entries, _ := os.ReadDir(hp)
			for _, e := range entries {
				if e.IsDir() {
					parseHistory(filepath.Join(hp, e.Name()), r, &events)
				}
			}
		} else {
			parseHistory(hp, r, &events)
		}
	}
	for _, logPath := range []string{"/var/log/auth.log", "/var/log/secure"} {
		if _, err := os.Stat(logPath); err == nil {
			parseAuthLog(logPath, r, &events)
		}
	}
	parseCron(r, &events)
	parseWtmp("/var/log/wtmp", r, &events)

	sort.Slice(events, func(i, j int) bool { return events[i].TS.Before(events[j].TS) })
	r.AddExtra("timeline", events)
	r.AddExtra("event_count", len(events))
	r.Finish()
	return r, nil
}

var _ = reDomain
var _ = reHash
