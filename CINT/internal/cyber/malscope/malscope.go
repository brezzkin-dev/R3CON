package malscope

import (
	"bufio"
	"debug/elf"
	"debug/pe"
	"encoding/binary"
	"hash/fnv"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	core "github.com/brezzkin-dev/CINT/internal/cyber/core"
)

var reStr = regexp.MustCompile(`[\x20-\x7e]{4,}`)

var suspiciousAPIs = map[string]core.Severity{
	"VirtualAllocEx":             core.SevHigh,
	"WriteProcessMemory":         core.SevHigh,
	"CreateRemoteThread":         core.SevCrit,
	"NtCreateThreadEx":           core.SevHigh,
	"SetWindowsHookEx":           core.SevMed,
	"GetAsyncKeyState":           core.SevHigh,
	"URLDownloadToFileA":         core.SevHigh,
	"URLDownloadToFileW":         core.SevHigh,
	"InternetOpenUrlA":           core.SevHigh,
	"WinExec":                    core.SevHigh,
	"ShellExecuteA":              core.SevMed,
	"ShellExecuteW":              core.SevMed,
	"CryptEncrypt":               core.SevMed,
	"CryptDecrypt":               core.SevMed,
	"AdjustTokenPrivileges":      core.SevHigh,
	"OpenProcessToken":           core.SevMed,
	"IsDebuggerPresent":          core.SevLow,
	"CheckRemoteDebuggerPresent": core.SevLow,
	"NtQueryInformationProcess":  core.SevMed,
}

type Section struct {
	Name    string  `json:"name"`
	Size    uint64  `json:"size"`
	Entropy float64 `json:"entropy"`
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

func roundTo(f float64, p int) float64 {
	pow := math.Pow(10, float64(p))
	return math.Round(f*pow) / pow
}

func imphash(funcs []string) string {
	lower := make([]string, 0, len(funcs))
	for _, f := range funcs {
		lower = append(lower, strings.ToLower(f))
	}
	sort.Strings(lower)
	h := fnv.New64a()
	for i, f := range lower {
		if i > 0 {
			h.Write([]byte(","))
		}
		h.Write([]byte(f))
	}
	return hexUint64(h.Sum64())
}

func hexUint64(v uint64) string {
	const hex = "0123456789abcdef"
	var b [16]byte
	for i := 15; i >= 0; i-- {
		b[i] = hex[v&0xf]
		v >>= 4
	}
	return string(b[:])
}

func detectOverlay(f *pe.File, fileSize int64) int64 {
	var lastEnd int64
	for _, s := range f.Sections {
		end := int64(s.Offset) + int64(s.Size)
		if end > lastEnd {
			lastEnd = end
		}
	}
	if fileSize > lastEnd {
		return fileSize - lastEnd
	}
	return 0
}

func analyzePE(path string, r *core.Result, yaraPath string) error {
	f, err := pe.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	data, _ := os.ReadFile(path)
	r.AddExtra("format", "pe")
	r.AddExtra("arch", archName(f.Machine))
	r.AddExtra("compile_time_unix", f.FileHeader.TimeDateStamp)

	var secs []Section
	for _, s := range f.Sections {
		raw, _ := s.Data()
		ent := roundTo(entropy(raw), 3)
		secs = append(secs, Section{Name: s.Name, Size: uint64(len(raw)), Entropy: ent})
		if len(raw) > 512 && ent > 7.2 {
			r.Add(core.Finding{
				Tool: "malscope", Severity: core.SevHigh,
				Title:    "Packed section: " + s.Name,
				Evidence: map[string]any{"entropy": ent, "size": len(raw)},
			})
		}
	}
	r.AddExtra("sections", secs)

	overlay := detectOverlay(f, int64(len(data)))
	if overlay > 0 {
		sev := core.SevMed
		if overlay > 1024*1024 {
			sev = core.SevHigh
		}
		r.Add(core.Finding{
			Tool: "malscope", Severity: sev,
			Title:    "PE overlay detected",
			Detail:   "payload appended after last section",
			Evidence: map[string]any{"overlay_bytes": overlay},
		})
	}

	if imports, err := f.ImportedSymbols(); err == nil {
		hash := imphash(imports)
		r.AddExtra("imphash", hash)
		var hits []string
		for _, imp := range imports {
			if sev, ok := suspiciousAPIs[imp]; ok {
				hits = append(hits, imp)
				r.Add(core.Finding{
					Tool: "malscope", Severity: sev,
					Title: "Suspicious import: " + imp,
				})
			}
		}
		r.AddExtra("suspicious_imports", hits)
	}

	addStrings(r, data)
	runYara(r, data, yaraPath)
	return nil
}

func analyzeELF(path string, r *core.Result, yaraPath string) error {
	f, err := elf.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	r.AddExtra("format", "elf")
	r.AddExtra("arch", f.Machine.String())
	var secs []Section
	for _, s := range f.Sections {
		raw, _ := s.Data()
		secs = append(secs, Section{Name: s.Name, Size: uint64(len(raw)), Entropy: roundTo(entropy(raw), 3)})
	}
	r.AddExtra("sections", secs)
	data, _ := os.ReadFile(path)
	addStrings(r, data)
	runYara(r, data, yaraPath)
	return nil
}

func addStrings(r *core.Result, data []byte) {
	if len(data) < 4 {
		return
	}
	matches := reStr.FindAll(data, -1)
	urls := []string{}
	seen := map[string]bool{}
	for _, m := range matches {
		s := string(m)
		if strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") {
			if !seen[s] {
				seen[s] = true
				urls = append(urls, s)
				if len(urls) >= 32 {
					break
				}
			}
		}
	}
	if len(urls) > 0 {
		r.Add(core.Finding{
			Tool: "malscope", Severity: core.SevMed,
			Title:    "Embedded URLs",
			Detail:   strings.Join(urls[:minInt(5, len(urls))], "; "),
			Evidence: map[string]any{"urls": urls},
		})
		r.AddExtra("urls", urls)
	}
	r.AddExtra("entropy_overall", roundTo(entropy(data), 3))
}

func Analyze(path, yaraPath string) (*core.Result, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	head := make([]byte, 4)
	f.Read(head)
	f.Close()

	r := core.NewResult("malscope", path)
	var aerr error
	switch {
	case head[0] == 'M' && head[1] == 'Z':
		aerr = analyzePE(path, r, yaraPath)
	case head[0] == 0x7f && head[1] == 'E' && head[2] == 'L' && head[3] == 'F':
		aerr = analyzeELF(path, r, yaraPath)
	default:
		data, _ := os.ReadFile(path)
		r.AddExtra("format", "unknown")
		r.AddExtra("size", len(data))
		addStrings(r, data)
		runYara(r, data, yaraPath)
	}
	if aerr != nil {
		return r, aerr
	}
	r.Finish()
	return r, nil
}

func archName(m uint16) string {
	switch m {
	case pe.IMAGE_FILE_MACHINE_AMD64:
		return "x86_64"
	case pe.IMAGE_FILE_MACHINE_I386:
		return "x86"
	case pe.IMAGE_FILE_MACHINE_ARM64:
		return "arm64"
	}
	return "unknown"
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

var _ = bufio.NewReader
var _ = binary.LittleEndian
var _ = filepath.Separator
