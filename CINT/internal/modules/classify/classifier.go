package classify

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/brezzkin-dev/CINT/internal/core"
	"github.com/brezzkin-dev/CINT/internal/magic"
)

type Rule struct {
	Name     string
	Kind     string
	Pattern  string
	MinSize  int64
	MaxSize  int64
	Severity string
	Desc     string
}

type Result struct {
	File     core.FileEntry `json:"file"`
	Category string         `json:"category"`
	Reason   string         `json:"reason"`
	Severity string         `json:"severity"`
}

var DefaultRules = []Rule{
	{"temp", "ext", ".tmp", 0, -1, "low", "temporary file"},
	{"temp", "ext", ".bak", 0, -1, "low", "backup file"},
	{"temp", "ext", ".swp", 0, -1, "low", "vim swap"},
	{"archive", "ext", ".zip", 0, -1, "info", "zip archive"},
	{"archive", "ext", ".tar", 0, -1, "info", "tar archive"},
	{"archive", "ext", ".gz", 0, -1, "info", "gzip"},
	{"executable", "ext", ".exe", 0, -1, "high", "windows executable"},
	{"executable", "ext", ".dll", 0, -1, "high", "windows library"},
	{"executable", "ext", ".so", 0, -1, "high", "shared object"},
	{"script", "ext", ".sh", 0, -1, "info", "shell script"},
	{"script", "ext", ".py", 0, -1, "info", "python script"},
	{"config", "ext", ".yml", 0, -1, "info", "yaml config"},
	{"config", "ext", ".yaml", 0, -1, "info", "yaml config"},
	{"key", "ext", ".pem", 0, -1, "high", "pem key"},
	{"key", "ext", ".key", 0, -1, "high", "private key"},
	{"empty", "size", "", 0, 0, "low", "zero-byte"},
	{"large", "size", "", 100 * 1024 * 1024, -1, "medium", "over 100MB"},
}

func Classify(entries []core.FileEntry, rules []Rule) []Result {
	if len(rules) == 0 {
		rules = DefaultRules
	}
	var out []Result
	for _, e := range entries {
		if e.IsDir {
			continue
		}
		var cat, reason, sev string
		if mime, desc, ok := detectMagic(e.Path); ok {
			cat = "magic:" + desc
			reason = mime
			sev = "info"
			if strings.Contains(mime, "exec") || strings.Contains(mime, "elf") || strings.Contains(mime, "mach") {
				sev = "high"
			}
		}
		for _, r := range rules {
			if !ruleMatches(r, e) {
				continue
			}
			if cat == "" {
				cat, reason, sev = r.Name, r.Desc, r.Severity
			} else if rank(r.Severity) > rank(sev) {
				sev = r.Severity
				reason += " + " + r.Desc
			}
		}
		if cat == "" {
			cat, reason, sev = "other", "unclassified", "info"
		}
		out = append(out, Result{File: e, Category: cat, Reason: reason, Severity: sev})
	}
	return out
}

func ruleMatches(r Rule, e core.FileEntry) bool {
	switch r.Kind {
	case "ext":
		return e.Ext == r.Pattern
	case "size":
		if r.MaxSize >= 0 && e.Size > r.MaxSize {
			return false
		}
		return e.Size >= r.MinSize
	case "name":
		ok, _ := filepath.Match(r.Pattern, filepath.Base(e.Path))
		return ok
	}
	return false
}

func detectMagic(path string) (string, string, bool) {
	f, err := os.Open(path)
	if err != nil {
		return "", "", false
	}
	defer f.Close()
	head := make([]byte, 512)
	n, _ := f.Read(head)
	if n == 0 {
		return "", "", false
	}
	return magic.Detect(head[:n])
}

func rank(s string) int {
	switch s {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	}
	return 1
}
