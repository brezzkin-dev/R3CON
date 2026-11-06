package malscope

import (
	"bufio"
	"os"
	"strings"

	core "github.com/brezzkin-dev/CINT/internal/cyber/core"
)

type yaraRule struct {
	Name      string
	Strings   [][]byte
	Condition string
}

var builtinRules = []yaraRule{
	{Name: "Mimikatz_Legacy", Strings: [][]byte{
		[]byte("sekurlsa::logonpasswords"),
		[]byte("gentilkiwi"),
		[]byte("dpapi::masterkey"),
	}, Condition: "any of them"},
	{Name: "Cobalt_Strike_Beacon", Strings: [][]byte{
		[]byte("beacon.dll"),
		[]byte("cobaltstrike"),
	}, Condition: "any of them"},
	{Name: "Emotet_Loader", Strings: [][]byte{
		[]byte("Emotet"),
		[]byte("LoadLibraryA"),
		[]byte("VirtualAlloc"),
	}, Condition: "all of them"},
	{Name: "Ransomware_Note", Strings: [][]byte{
		[]byte("YOUR FILES ARE ENCRYPTED"),
		[]byte("bitcoin"),
		[]byte("decrypt"),
	}, Condition: "any of them"},
	{Name: "Meterpreter", Strings: [][]byte{
		[]byte("metsrv"),
		[]byte("stdapi"),
		[]byte("ReflectiveLoader"),
	}, Condition: "any of them"},
	{Name: "UPX_Packed", Strings: [][]byte{
		[]byte("UPX0"),
		[]byte("UPX1"),
		[]byte("UPX!"),
	}, Condition: "all of them"},
	{Name: "Crypto_Clue", Strings: [][]byte{
		[]byte("CryptEncrypt"),
		[]byte("CryptDecrypt"),
		[]byte("CryptGenKey"),
	}, Condition: "any of them"},
	{Name: "Keylogger_Clue", Strings: [][]byte{
		[]byte("SetWindowsHookEx"),
		[]byte("WH_KEYBOARD"),
		[]byte("GetForegroundWindow"),
	}, Condition: "all of them"},
	{Name: "ReverseShell_Clue", Strings: [][]byte{
		[]byte("WSAStartup"),
		[]byte("connect"),
		[]byte("cmd.exe"),
	}, Condition: "all of them"},
	{Name: "Persistence_Clue", Strings: [][]byte{
		[]byte("CurrentVersion\\Run"),
		[]byte("RegSetValueEx"),
	}, Condition: "all of them"},
}

func loadCustomRules(path string) ([]yaraRule, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var rules []yaraRule
	sc := bufio.NewScanner(f)
	var cur *yaraRule
	inStrings := false
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "//") || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "rule ") {
			name := strings.TrimSuffix(strings.TrimPrefix(line, "rule "), " {")
			name = strings.TrimSpace(name)
			cur = &yaraRule{Name: name}
			continue
		}
		if cur == nil {
			continue
		}
		if strings.HasPrefix(line, "strings:") {
			inStrings = true
			continue
		}
		if strings.HasPrefix(line, "condition:") {
			cond := strings.TrimSpace(strings.TrimPrefix(line, "condition:"))
			cur.Condition = cond
			inStrings = false
			continue
		}
		if line == "}" {
			if cur.Name != "" && len(cur.Strings) > 0 {
				rules = append(rules, *cur)
			}
			cur = nil
			inStrings = false
			continue
		}
		if inStrings && strings.HasPrefix(line, "$") {
			eqIdx := strings.Index(line, "=")
			if eqIdx < 0 {
				continue
			}
			val := strings.TrimSpace(line[eqIdx+1:])
			if strings.HasPrefix(val, "\"") && strings.HasSuffix(val, "\"") {
				cur.Strings = append(cur.Strings, []byte(val[1:len(val)-1]))
			} else if strings.HasPrefix(val, "{") && strings.HasSuffix(val, "}") {
				hexs := strings.TrimSpace(val[1 : len(val)-1])
				raw := strings.Fields(hexs)
				buf := make([]byte, 0, len(raw))
				for _, h := range raw {
					if len(h) == 2 {
						buf = append(buf, hexByte(h))
					}
				}
				if len(buf) > 0 {
					cur.Strings = append(cur.Strings, buf)
				}
			}
		}
	}
	return rules, nil
}

func hexByte(s string) byte {
	var b byte
	for i := 0; i < len(s); i++ {
		b <<= 4
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
			b |= c - '0'
		case c >= 'a' && c <= 'f':
			b |= c - 'a' + 10
		case c >= 'A' && c <= 'F':
			b |= c - 'A' + 10
		}
	}
	return b
}

func runYara(r *core.Result, data []byte, customPath string) {
	rules := append([]yaraRule{}, builtinRules...)
	if customPath != "" {
		if extra, err := loadCustomRules(customPath); err == nil {
			rules = append(rules, extra...)
		}
	}

	var matches []string
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
		fire := false
		switch rule.Condition {
		case "all of them":
			fire = matched == len(rule.Strings)
		default:
			fire = matched > 0
		}
		if fire {
			matches = append(matches, rule.Name)
			sev := core.SevHigh
			if strings.Contains(rule.Name, "Mimikatz") ||
				strings.Contains(rule.Name, "Cobalt") ||
				strings.Contains(rule.Name, "Meterpreter") ||
				strings.Contains(rule.Name, "Ransomware") {
				sev = core.SevCrit
			}
			r.Add(core.Finding{
				Tool: "malscope", Severity: sev,
				Title:    "YARA match: " + rule.Name,
				Detail:   rule.Condition,
				Evidence: map[string]any{"matched_strings": matched, "total": len(rule.Strings)},
			})
		}
	}
	if len(matches) > 0 {
		r.AddExtra("yara_matches", matches)
	}
}

func containsBytes(haystack, needle []byte) bool {
	if len(needle) == 0 || len(haystack) < len(needle) {
		return false
	}
	for i := 0; i <= len(haystack)-len(needle); i++ {
		match := true
		for j := 0; j < len(needle); j++ {
			if haystack[i+j] != needle[j] {
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
