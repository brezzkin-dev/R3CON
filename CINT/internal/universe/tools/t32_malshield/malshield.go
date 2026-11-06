package t32_malshield

import (
	"debug/elf"
	"fmt"
	"math"
	"os"
	"regexp"
	"sort"
	"strings"

	core "github.com/brezzkin-dev/CINT/internal/universe/core"
)

var (
	reStr = regexp.MustCompile(`[\x20-\x7e]{4,}`)
	reURL = regexp.MustCompile(`https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{6,}`)
	reIP  = regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b`)
)

var suspiciousAPIs = map[string]core.Severity{
	"VirtualAllocEx":             core.SevHigh,
	"WriteProcessMemory":         core.SevHigh,
	"CreateRemoteThread":         core.SevCrit,
	"NtCreateThreadEx":           core.SevHigh,
	"RtlCreateUserThread":        core.SevHigh,
	"SetWindowsHookExA":          core.SevMed,
	"SetWindowsHookExW":          core.SevMed,
	"GetAsyncKeyState":           core.SevHigh,
	"URLDownloadToFileA":         core.SevHigh,
	"URLDownloadToFileW":         core.SevHigh,
	"InternetOpenUrlA":           core.SevHigh,
	"InternetOpenUrlW":           core.SevHigh,
	"WinExec":                    core.SevHigh,
	"ShellExecuteA":              core.SevMed,
	"ShellExecuteW":              core.SevMed,
	"CryptEncrypt":               core.SevMed,
	"CryptDecrypt":               core.SevMed,
	"CryptGenKey":                core.SevMed,
	"AdjustTokenPrivileges":      core.SevHigh,
	"OpenProcessToken":           core.SevMed,
	"IsDebuggerPresent":          core.SevLow,
	"CheckRemoteDebuggerPresent": core.SevLow,
	"NtQueryInformationProcess":  core.SevMed,
	"RegSetValueExA":             core.SevMed,
	"RegSetValueExW":             core.SevMed,
	"RegCreateKeyExA":            core.SevMed,
	"RegCreateKeyExW":            core.SevMed,
	"LoadLibraryA":               core.SevLow,
	"LoadLibraryW":               core.SevLow,
	"GetProcAddress":             core.SevLow,
	"WSASocketA":                 core.SevMed,
	"WSASocketW":                 core.SevMed,
}

func Run(path string) (*core.Result, error) {
	r := core.NewResult("malshield", path)
	data, err := os.ReadFile(path)
	if err != nil {
		return r, err
	}

	r.AddExtra("size", len(data))
	r.AddExtra("sha256", sha256Hex(data))
	r.AddExtra("md5", md5Hex(data))
	r.AddExtra("sha1", sha1Hex(data))
	r.AddExtra("overall_entropy", roundf(entropy(data), 3))

	if len(data) >= 2 && data[0] == 'M' && data[1] == 'Z' {
		if info, err := analyzePE(path, data); err == nil {
			r.AddExtra("pe", info)
			emitPEFindings(r, info)
		}
	} else if len(data) >= 4 && data[0] == 0x7f && data[1] == 'E' && data[2] == 'L' && data[3] == 'F' {
		if info, err := analyzeELF(path); err == nil {
			r.AddExtra("elf", info)
			emitELFFindings(r, info)
		}
	}

	lower := strings.ToLower(string(data))
	var apiHits []string
	for api, sev := range suspiciousAPIs {
		if strings.Contains(lower, strings.ToLower(api)) {
			apiHits = append(apiHits, api)
			r.Add(core.Finding{
				Tool: "malshield", Severity: sev,
				Title: "API: " + api,
			})
		}
	}
	sort.Strings(apiHits)
	r.AddExtra("api_hits", apiHits)

	urls := uniqueStrings(reURL.FindAllString(string(data), 50))
	ips := uniqueStrings(reIP.FindAllString(string(data), 50))
	r.AddExtra("urls", urls)
	r.AddExtra("ips", ips)
	if len(urls) > 0 {
		r.Add(core.Finding{Tool: "malshield", Severity: core.SevMed,
			Title:  fmt.Sprintf("%d embedded URLs", len(urls)),
			Detail: strings.Join(urls[:minInt(3, len(urls))], "; ")})
	}

	runYara(r, data, "")

	score := 0
	for _, f := range r.Findings {
		switch f.Severity {
		case core.SevCrit:
			score += 30
		case core.SevHigh:
			score += 15
		case core.SevMed:
			score += 5
		}
	}
	r.AddExtra("malware_score", score)
	switch {
	case score >= 60:
		r.AddExtra("verdict", "highly likely malicious")
	case score >= 30:
		r.AddExtra("verdict", "suspicious — analyst review advised")
	default:
		r.AddExtra("verdict", "no strong malicious signals")
	}

	r.Finish()
	return r, nil
}

func emitPEFindings(r *core.Result, info *peInfo) {
	for _, s := range info.Sections {
		if s.RawSize > 512 && s.Entropy > 7.2 {
			r.Add(core.Finding{
				Tool: "malshield", Severity: core.SevHigh,
				Title:    "Packed section: " + s.Name,
				Evidence: map[string]any{"entropy": s.Entropy, "raw_size": s.RawSize},
			})
		}
	}
	if info.Overlay > 1024 {
		r.Add(core.Finding{
			Tool: "malshield", Severity: core.SevMed,
			Title:  "PE overlay",
			Detail: fmt.Sprintf("%d bytes appended after last section", info.Overlay),
		})
	}
}

type elfInfo struct {
	Machine  string   `json:"machine"`
	Entry    uint64   `json:"entry"`
	Sections []elfSec `json:"sections"`
	Needed   []string `json:"needed"`
}

type elfSec struct {
	Name    string  `json:"name"`
	Size    uint64  `json:"size"`
	Entropy float64 `json:"entropy"`
}

func analyzeELF(path string) (*elfInfo, error) {
	f, err := elf.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info := &elfInfo{Machine: f.Machine.String(), Entry: f.Entry}
	for _, s := range f.Sections {
		raw, _ := s.Data()
		info.Sections = append(info.Sections, elfSec{
			Name: s.Name, Size: s.Size, Entropy: roundf(entropy(raw), 3),
		})
	}
	if needed, err := f.ImportedLibraries(); err == nil {
		info.Needed = needed
	}
	return info, nil
}

func emitELFFindings(r *core.Result, info *elfInfo) {
	for _, s := range info.Sections {
		if s.Size > 512 && s.Entropy > 7.2 {
			r.Add(core.Finding{
				Tool: "malshield", Severity: core.SevHigh,
				Title:    "Packed section: " + s.Name,
				Evidence: map[string]any{"entropy": s.Entropy, "size": s.Size},
			})
		}
	}
}

func entropy(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	var counts [256]int
	for _, c := range b {
		counts[c]++
	}
	n := float64(len(b))
	var h float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}

func roundf(f float64, p int) float64 {
	m := math.Pow(10, float64(p))
	return math.Round(f*m) / m
}

func uniqueStrings(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

var _ = reStr
