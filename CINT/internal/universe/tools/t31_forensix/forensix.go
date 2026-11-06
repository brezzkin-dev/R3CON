package t31_forensix

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	core "github.com/brezzkin-dev/CINT/internal/universe/core"
)

type Options struct {
	Root       string
	RecentDays int
}

type Event struct {
	TS     time.Time `json:"-"`
	TSStr  string    `json:"ts"`
	Kind   string    `json:"kind"`
	Path   string    `json:"path"`
	Detail string    `json:"detail,omitempty"`
}

type Artifact struct {
	Kind   string `json:"kind"`
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	MTime  string `json:"mtime"`
	Detail string `json:"detail,omitempty"`
}

var reURL = regexp.MustCompile(`https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{6,}`)
var reSuspicious = regexp.MustCompile(`(?i)(curl\s+[^|]*\|\s*sh|wget\s+[^|]*\|\s*sh|base64\s+-d|python\s+-c|perl\s+-e|nc\s+-[le]|chmod\s+\+x|/tmp/\S+)`)

func Run(opts Options) (*core.Result, error) {
	root := opts.Root
	if root == "" {
		if h, err := os.UserHomeDir(); err == nil {
			root = h
		} else {
			return nil, fmt.Errorf("cannot determine home dir")
		}
	}
	if opts.RecentDays < 1 {
		opts.RecentDays = 7
	}

	r := core.NewResult("forensix", root)
	r.AddExtra("root", root)
	r.AddExtra("recent_days", opts.RecentDays)

	var events []Event
	var artifacts []Artifact

	for _, name := range []string{".bash_history", ".zsh_history", ".sh_history", ".python_history", ".mysql_history"} {
		p := filepath.Join(root, name)
		if info, err := os.Stat(p); err == nil {
			a := Artifact{Kind: "shell_history", Path: p, Size: info.Size(),
				MTime: info.ModTime().UTC().Format(time.RFC3339)}
			artifacts = append(artifacts, a)
			events = append(events, Event{TS: info.ModTime(), Kind: "shell_history_mtime", Path: p})
			scanHistoryFile(p, r, &events)
		}
	}

	browserPatterns := map[string][]string{
		"firefox": {
			".mozilla/firefox/*/places.sqlite",
			".mozilla/firefox/*/cookies.sqlite",
			"snap/firefox/common/.mozilla/firefox/*/places.sqlite",
		},
		"chrome": {
			".config/google-chrome/*/History",
			".config/google-chrome/*/Cookies",
			".config/google-chrome/*/Login Data",
		},
		"chromium": {
			".config/chromium/*/History",
			".config/chromium/*/Cookies",
		},
		"brave": {
			".config/BraveSoftware/Brave-Browser/*/History",
		},
		"edge": {
			".config/microsoft-edge/*/History",
		},
	}
	for browser, patterns := range browserPatterns {
		for _, pat := range patterns {
			matches, _ := filepath.Glob(filepath.Join(root, pat))
			for _, m := range matches {
				info, err := os.Stat(m)
				if err != nil {
					continue
				}
				a := Artifact{Kind: "browser_" + browser, Path: m, Size: info.Size(),
					MTime: info.ModTime().UTC().Format(time.RFC3339)}
				artifacts = append(artifacts, a)
				if strings.HasSuffix(m, "History") || strings.HasSuffix(m, "places.sqlite") {
					urls := extractURLsFromFile(m, 500)
					if len(urls) > 0 {
						r.AddExtra(browser+"_urls", urls)
						r.Add(core.Finding{Tool: "forensix", Severity: core.SevInfo,
							Title:  fmt.Sprintf("%s history: %d URLs", browser, len(urls)),
							Detail: m})
						for _, u := range urls[:minInt(10, len(urls))] {
							events = append(events, Event{
								TS: info.ModTime(), Kind: "browser_url", Path: m, Detail: u,
							})
						}
					}
				}
			}
		}
	}

	for _, pat := range []string{
		"*/systemd/user/*.service",
		"*/.config/systemd/user/*.service",
		"*/.config/autostart/*.desktop",
	} {
		matches, _ := filepath.Glob(filepath.Join(root, pat))
		for _, m := range matches {
			info, err := os.Stat(m)
			if err != nil {
				continue
			}
			artifacts = append(artifacts, Artifact{
				Kind: "startup_item", Path: m, Size: info.Size(),
				MTime: info.ModTime().UTC().Format(time.RFC3339),
			})
			if detail := scanStartupFile(m); detail != "" {
				r.Add(core.Finding{Tool: "forensix", Severity: core.SevMed,
					Title: "Suspicious startup entry", Detail: detail,
					Evidence: map[string]any{"path": m}})
			}
		}
	}

	for _, pat := range []string{
		"/etc/systemd/system/*.service",
		"/etc/init.d/*",
	} {
		matches, _ := filepath.Glob(pat)
		for _, m := range matches {
			info, err := os.Stat(m)
			if err != nil {
				continue
			}
			artifacts = append(artifacts, Artifact{
				Kind: "system_startup", Path: m, Size: info.Size(),
				MTime: info.ModTime().UTC().Format(time.RFC3339),
			})
		}
	}

	cutoff := time.Now().AddDate(0, 0, -opts.RecentDays)
	filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if info.ModTime().After(cutoff) {
			artifacts = append(artifacts, Artifact{
				Kind: "recent_file", Path: p, Size: info.Size(),
				MTime: info.ModTime().UTC().Format(time.RFC3339),
			})
			events = append(events, Event{TS: info.ModTime(), Kind: "recent_file", Path: p})
		}
		return nil
	})

	if info, err := os.Stat("/var/log/dpkg.log"); err == nil {
		artifacts = append(artifacts, Artifact{
			Kind: "dpkg_log", Path: "/var/log/dpkg.log", Size: info.Size(),
			MTime: info.ModTime().UTC().Format(time.RFC3339),
		})
		scanDpkgLog("/var/log/dpkg.log", &events)
	}

	sort.Slice(events, func(i, j int) bool { return events[i].TS.Before(events[j].TS) })
	for i := range events {
		events[i].TSStr = events[i].TS.UTC().Format(time.RFC3339)
	}

	sort.Slice(artifacts, func(i, j int) bool { return artifacts[i].MTime < artifacts[j].MTime })

	r.AddExtra("artifacts", artifacts)
	r.AddExtra("timeline", events)
	r.AddExtra("artifact_count", len(artifacts))
	r.AddExtra("event_count", len(events))

	counts := map[string]int{}
	for _, a := range artifacts {
		counts[a.Kind]++
	}
	if len(counts) > 0 {
		r.Add(core.Finding{Tool: "forensix", Severity: core.SevInfo,
			Title: fmt.Sprintf("%d artifacts across %d kinds", len(artifacts), len(counts))})
	}
	if recentCount := counts["recent_file"]; recentCount > 100 {
		r.Add(core.Finding{Tool: "forensix", Severity: core.SevMed,
			Title: fmt.Sprintf("%d files modified in last %d days", recentCount, opts.RecentDays)})
	}

	r.Finish()
	return r, nil
}

func scanHistoryFile(p string, r *core.Result, events *[]Event) {
	f, err := os.Open(p)
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 4096), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if reSuspicious.MatchString(line) {
			r.Add(core.Finding{Tool: "forensix", Severity: core.SevHigh,
				Title:    "Suspicious shell command",
				Detail:   line,
				Evidence: map[string]any{"file": p}})
		}
		for _, u := range reURL.FindAllString(line, 5) {
			*events = append(*events, Event{
				TS: time.Now().UTC(), Kind: "history_url", Path: p, Detail: u,
			})
		}
	}
}

func scanStartupFile(p string) string {
	data, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		if reSuspicious.MatchString(line) {
			return p + ": " + strings.TrimSpace(line)
		}
	}
	return ""
}

func extractURLsFromFile(p string, max int) []string {
	data, err := os.ReadFile(p)
	if err != nil {
		return nil
	}
	matches := reURL.FindAll(data, max*3)
	seen := map[string]bool{}
	var out []string
	for _, m := range matches {
		s := string(m)
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
		if len(out) >= max {
			break
		}
	}
	return out
}

func scanDpkgLog(p string, events *[]Event) {
	f, err := os.Open(p)
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 4096), 1<<20)
	count := 0
	for sc.Scan() && count < 500 {
		line := sc.Text()
		if len(line) < 20 {
			continue
		}
		ts, err := time.Parse("2006-01-02 15:04:05", line[:19])
		if err != nil {
			continue
		}
		if strings.Contains(line, " install ") || strings.Contains(line, " upgrade ") ||
			strings.Contains(line, " remove ") {
			*events = append(*events, Event{TS: ts, Kind: "dpkg", Detail: line[20:]})
			count++
		}
	}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
