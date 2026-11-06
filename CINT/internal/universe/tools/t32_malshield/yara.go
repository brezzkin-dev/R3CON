package t32_malshield

import (
	"os"
	"regexp"
	"strings"

	core "github.com/brezzkin-dev/CINT/internal/universe/core"
)

type rule struct {
	Name     string
	Severity core.Severity
	Strings  [][]byte
	AllMust  bool
	Mitre    string
	Desc     string
}

var builtinRules = []rule{
	{Name: "mimikatz", Severity: core.SevCrit, Mitre: "T1003",
		Desc: "credential dumping", AllMust: false,
		Strings: [][]byte{
			[]byte("sekurlsa::logonpasswords"),
			[]byte("gentilkiwi"),
			[]byte("dpapi::masterkey"),
			[]byte("lsadump::sam"),
		}},
	{Name: "cobaltstrike_beacon", Severity: core.SevCrit, Mitre: "T1071",
		Desc: "C2 framework", AllMust: false,
		Strings: [][]byte{
			[]byte("beacon.dll"),
			[]byte("cobaltstrike"),
			[]byte("sleeptime"),
			[]byte("jitter"),
		}},
	{Name: "meterpreter", Severity: core.SevCrit, Mitre: "T1055",
		Desc: "Metasploit payload", AllMust: false,
		Strings: [][]byte{
			[]byte("metsrv"),
			[]byte("stdapi"),
			[]byte("ReflectiveLoader"),
			[]byte("priv_passwd"),
		}},
	{Name: "ransomware_note", Severity: core.SevCrit, Mitre: "T1486",
		Desc: "ransomware", AllMust: false,
		Strings: [][]byte{
			[]byte("YOUR FILES ARE ENCRYPTED"),
			[]byte("bitcoin"),
			[]byte("decrypt"),
			[]byte("-----BEGIN PUBLIC KEY-----"),
		}},
	{Name: "keylogger_api", Severity: core.SevHigh, Mitre: "T1056",
		Desc: "keystroke capture", AllMust: true,
		Strings: [][]byte{
			[]byte("SetWindowsHookEx"),
			[]byte("GetAsyncKeyState"),
			[]byte("GetForegroundWindow"),
		}},
	{Name: "reverse_shell", Severity: core.SevHigh, Mitre: "T1059",
		Desc: "reverse shell", AllMust: true,
		Strings: [][]byte{
			[]byte("WSAStartup"),
			[]byte("connect"),
			[]byte("cmd.exe"),
		}},
	{Name: "persistence_run_key", Severity: core.SevMed, Mitre: "T1547",
		Desc: "registry Run persistence", AllMust: true,
		Strings: [][]byte{
			[]byte("CurrentVersion\\Run"),
			[]byte("RegSetValueEx"),
		}},
	{Name: "upx_packed", Severity: core.SevMed, Mitre: "T1027",
		Desc: "UPX packed", AllMust: true,
		Strings: [][]byte{
			[]byte("UPX0"),
			[]byte("UPX1"),
			[]byte("UPX!"),
		}},
	{Name: "amsi_bypass", Severity: core.SevHigh, Mitre: "T1562",
		Desc: "AMSI bypass", AllMust: false,
		Strings: [][]byte{
			[]byte("AmsiScanBuffer"),
			[]byte("amsiContext"),
			[]byte("[Ref].Assembly.GetType"),
		}},
	{Name: "anti_debug", Severity: core.SevMed, Mitre: "T1622",
		Desc: "debugger detection", AllMust: true,
		Strings: [][]byte{
			[]byte("IsDebuggerPresent"),
			[]byte("CheckRemoteDebuggerPresent"),
		}},
	{Name: "byovd", Severity: core.SevHigh, Mitre: "T1068",
		Desc: "vulnerable driver", AllMust: false,
		Strings: [][]byte{
			[]byte("\\\\Device\\\\PhysicalMemory"),
			[]byte("\\\\Device\\\\PhysicalDrive"),
			[]byte("IoCreateDevice"),
		}},
	{Name: "clipboard_hijack", Severity: core.SevHigh, Mitre: "T1115",
		Desc: "clipboard hijack", AllMust: true,
		Strings: [][]byte{
			[]byte("OpenClipboard"),
			[]byte("SetClipboardData"),
			[]byte("GetClipboardData"),
		}},
}

var reRuleName = regexp.MustCompile(`(?m)^\s*rule\s+(\w+)`)
var reString = regexp.MustCompile(`(?m)^\s*\$\w+\s*=\s*"([^"]+)"`)
var reHexStr = regexp.MustCompile(`(?m)^\s*\$\w+\s*=\s*\{\s*([0-9A-Fa-f\s]+)\s*\}`)
var reCondition = regexp.MustCompile(`(?m)^\s*condition\s*:\s*(.+)$`)

func loadCustomRules(path string) []rule {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	blocks := splitRuleBlocks(string(data))
	var out []rule
	for _, b := range blocks {
		nameM := reRuleName.FindStringSubmatch(b)
		if len(nameM) < 2 {
			continue
		}
		r := rule{Name: nameM[1], Severity: core.SevHigh}
		for _, m := range reString.FindAllStringSubmatch(b, -1) {
			r.Strings = append(r.Strings, []byte(m[1]))
		}
		for _, m := range reHexStr.FindAllStringSubmatch(b, -1) {
			hexStr := strings.ReplaceAll(m[1], " ", "")
			hexStr = strings.ReplaceAll(hexStr, "\n", "")
			hexStr = strings.ReplaceAll(hexStr, "\t", "")
			if len(hexStr)%2 != 0 {
				continue
			}
			buf := make([]byte, len(hexStr)/2)
			ok := true
			for i := 0; i < len(hexStr); i += 2 {
				hi := hexNibble(hexStr[i])
				lo := hexNibble(hexStr[i+1])
				if hi < 0 || lo < 0 {
					ok = false
					break
				}
				buf[i/2] = byte(hi<<4 | lo)
			}
			if ok {
				r.Strings = append(r.Strings, buf)
			}
		}
		if cond := reCondition.FindStringSubmatch(b); len(cond) > 1 {
			r.AllMust = strings.Contains(strings.ToLower(cond[1]), "all")
		}
		if len(r.Strings) > 0 {
			out = append(out, r)
		}
	}
	return out
}

func splitRuleBlocks(src string) []string {
	var blocks []string
	depth := 0
	start := -1
	for i, c := range src {
		if c == '{' {
			if depth == 0 {
				start = i
			}
			depth++
		} else if c == '}' {
			depth--
			if depth == 0 && start >= 0 {
				blocks = append(blocks, src[start:i+1])
				start = -1
			}
		}
	}
	return blocks
}

func hexNibble(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	}
	return -1
}

func runYara(r *core.Result, data []byte, customPath string) {
	rules := append([]rule{}, builtinRules...)
	if customPath != "" {
		rules = append(rules, loadCustomRules(customPath)...)
	}
	for _, rule := range rules {
		matched := 0
		for _, pat := range rule.Strings {
			if len(pat) == 0 {
				continue
			}
			if containsBytes(data, pat) {
				matched++
			}
		}
		fire := matched > 0
		if rule.AllMust {
			fire = matched == len(rule.Strings)
		}
		if fire {
			r.Add(core.Finding{
				Tool: "malshield", Severity: rule.Severity,
				Title:  "YARA: " + rule.Name,
				Detail: rule.Desc,
				Evidence: map[string]any{
					"mitre": rule.Mitre, "strings_matched": matched,
					"strings_total": len(rule.Strings),
				},
			})
		}
	}
}

func containsBytes(h, n []byte) bool {
	if len(n) == 0 || len(h) < len(n) {
		return false
	}
	first := n[0]
	for i := 0; i <= len(h)-len(n); i++ {
		if h[i] != first {
			continue
		}
		match := true
		for j := 1; j < len(n); j++ {
			if h[i+j] != n[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
