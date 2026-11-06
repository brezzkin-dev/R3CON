package t17_binarycore

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"debug/elf"
	"debug/pe"
	"encoding/hex"
	"fmt"
	"math"
	"os"
	"regexp"
	"sort"
	"strings"

	core "github.com/brezzkin-dev/CINT/internal/universe/core"
)

var reStr = regexp.MustCompile(`[\x20-\x7e]{4,}`)

var suspiciousAPIs = map[string]core.Severity{
	"VirtualAllocEx":             core.SevHigh,
	"VirtualProtectEx":           core.SevHigh,
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
	"AdjustTokenPrivileges":      core.SevHigh,
	"OpenProcessToken":           core.SevMed,
	"IsDebuggerPresent":          core.SevLow,
	"CheckRemoteDebuggerPresent": core.SevLow,
	"NtQueryInformationProcess":  core.SevMed,
	"RegSetValueExA":             core.SevMed,
	"RegSetValueExW":             core.SevMed,
	"LoadLibraryA":               core.SevLow,
	"LoadLibraryW":               core.SevLow,
	"GetProcAddress":             core.SevLow,
	"WSASocketA":                 core.SevMed,
	"WSASocketW":                 core.SevMed,
}

type Section struct {
	Name    string  `json:"name"`
	Size    uint64  `json:"size"`
	Entropy float64 `json:"entropy"`
	Vaddr   uint64  `json:"vaddr"`
}

type ImportGroup struct {
	DLL     string   `json:"dll"`
	Symbols []string `json:"symbols"`
}

func Run(path string) (*core.Result, error) {
	r := core.NewResult("binarycore", path)
	data, err := os.ReadFile(path)
	if err != nil {
		return r, err
	}
	r.AddExtra("size", len(data))

	md5h := md5.Sum(data)
	sha1h := sha1.Sum(data)
	sha256h := sha256.Sum256(data)
	r.AddExtra("md5", hex.EncodeToString(md5h[:]))
	r.AddExtra("sha1", hex.EncodeToString(sha1h[:]))
	r.AddExtra("sha256", hex.EncodeToString(sha256h[:]))

	switch {
	case len(data) >= 2 && data[0] == 'M' && data[1] == 'Z':
		return analyzePE(path, r, data)
	case len(data) >= 4 && data[0] == 0x7f && data[1] == 'E' && data[2] == 'L' && data[3] == 'F':
		return analyzeELF(path, r, data)
	}

	r.AddExtra("format", "unknown")
	sweepStrings(r, data)
	r.Finish()
	return r, nil
}

func analyzePE(path string, r *core.Result, data []byte) (*core.Result, error) {
	f, err := pe.Open(path)
	if err != nil {
		r.Add(core.Finding{Tool: "binarycore", Severity: core.SevHigh,
			Title: "PE parse failed", Detail: err.Error()})
		r.Finish()
		return r, nil
	}
	defer f.Close()

	r.AddExtra("format", "pe")
	r.AddExtra("machine", machineName(f.Machine))
	r.AddExtra("timestamp", f.FileHeader.TimeDateStamp)

	var secs []Section
	for _, s := range f.Sections {
		raw, _ := s.Data()
		secs = append(secs, Section{
			Name:    s.Name,
			Size:    uint64(len(raw)),
			Entropy: roundf(shannon(raw), 3),
			Vaddr:   uint64(s.VirtualAddress),
		})
		if len(raw) > 512 && shannon(raw) > 7.2 {
			r.Add(core.Finding{Tool: "binarycore", Severity: core.SevHigh,
				Title:    "Packed section: " + s.Name,
				Detail:   "entropy > 7.2",
				Evidence: map[string]any{"entropy": roundf(shannon(raw), 3), "size": len(raw)}})
		}
	}
	r.AddExtra("sections", secs)

	if opt, ok := f.OptionalHeader.(*pe.OptionalHeader64); ok {
		r.AddExtra("image_base", fmt.Sprintf("0x%x", opt.ImageBase))
		r.AddExtra("entry_point", fmt.Sprintf("0x%x", opt.AddressOfEntryPoint))
		r.AddExtra("subsystem", subsystemName(opt.Subsystem))
	} else if opt, ok := f.OptionalHeader.(*pe.OptionalHeader32); ok {
		r.AddExtra("image_base", fmt.Sprintf("0x%x", opt.ImageBase))
		r.AddExtra("entry_point", fmt.Sprintf("0x%x", opt.AddressOfEntryPoint))
		r.AddExtra("subsystem", subsystemName(opt.Subsystem))
	}

	if symbols, err := f.ImportedSymbols(); err == nil {
		grouped := map[string][]string{}
		for _, sym := range symbols {
			parts := strings.SplitN(sym, ".", 2)
			dll := "unknown"
			fn := sym
			if len(parts) == 2 {
				dll = parts[0]
				fn = parts[1]
			}
			grouped[dll] = append(grouped[dll], fn)
			if sev, ok := suspiciousAPIs[fn]; ok {
				r.Add(core.Finding{Tool: "binarycore", Severity: sev,
					Title: "Suspicious import: " + fn, Detail: "from " + dll})
			}
		}
		var groups []ImportGroup
		for dll, syms := range grouped {
			sort.Strings(syms)
			groups = append(groups, ImportGroup{DLL: dll, Symbols: syms})
		}
		r.AddExtra("imports", groups)
	}

	var lastEnd int64
	for _, s := range f.Sections {
		end := int64(s.Offset) + int64(s.Size)
		if end > lastEnd {
			lastEnd = end
		}
	}
	if int64(len(data)) > lastEnd {
		overlay := int64(len(data)) - lastEnd
		r.AddExtra("overlay_bytes", overlay)
		if overlay > 1024 {
			r.Add(core.Finding{Tool: "binarycore", Severity: core.SevMed,
				Title:  "PE overlay",
				Detail: fmt.Sprintf("%d bytes appended after last section", overlay)})
		}
	}

	sweepStrings(r, data)
	r.Finish()
	return r, nil
}

func analyzeELF(path string, r *core.Result, data []byte) (*core.Result, error) {
	f, err := elf.Open(path)
	if err != nil {
		r.Add(core.Finding{Tool: "binarycore", Severity: core.SevHigh,
			Title: "ELF parse failed", Detail: err.Error()})
		r.Finish()
		return r, nil
	}
	defer f.Close()

	r.AddExtra("format", "elf")
	r.AddExtra("machine", f.Machine.String())
	r.AddExtra("entry", fmt.Sprintf("0x%x", f.Entry))

	var secs []Section
	for _, s := range f.Sections {
		raw, _ := s.Data()
		secs = append(secs, Section{Name: s.Name, Size: s.Size, Entropy: roundf(shannon(raw), 3), Vaddr: s.Addr})
	}
	r.AddExtra("sections", secs)

	if needed, err := f.ImportedLibraries(); err == nil {
		r.AddExtra("needed", needed)
	}
	sweepStrings(r, data)
	r.Finish()
	return r, nil
}

func sweepStrings(r *core.Result, data []byte) {
	if len(data) < 4 {
		return
	}
	matches := reStr.FindAll(data, 2000)
	urls := []string{}
	seen := map[string]bool{}
	for _, m := range matches {
		s := string(m)
		if (strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://")) && !seen[s] {
			seen[s] = true
			urls = append(urls, s)
			if len(urls) >= 32 {
				break
			}
		}
	}
	if len(urls) > 0 {
		r.AddExtra("urls", urls)
		r.Add(core.Finding{Tool: "binarycore", Severity: core.SevMed,
			Title:  fmt.Sprintf("%d embedded URLs", len(urls)),
			Detail: strings.Join(urls[:minInt(3, len(urls))], "; ")})
	}
	r.AddExtra("overall_entropy", roundf(shannon(data), 3))
}

func machineName(m uint16) string {
	switch m {
	case pe.IMAGE_FILE_MACHINE_AMD64:
		return "x86_64"
	case pe.IMAGE_FILE_MACHINE_I386:
		return "x86"
	case pe.IMAGE_FILE_MACHINE_ARM64:
		return "arm64"
	}
	return fmt.Sprintf("unknown_0x%04x", m)
}

func subsystemName(s uint16) string {
	switch s {
	case 1:
		return "native"
	case 2:
		return "windows_gui"
	case 3:
		return "windows_console"
	}
	return fmt.Sprintf("unknown_%d", s)
}

func shannon(b []byte) float64 {
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

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
