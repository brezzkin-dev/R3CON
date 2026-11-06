package t16_memoryx

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io"
	"math"
	"os"
	"regexp"
	"strings"

	core "github.com/brezzkin-dev/CINT/internal/universe/core"
)

type Options struct {
	MinString int
}

type IOCSet struct {
	URLs     map[string]int `json:"urls"`
	IPv4     map[string]int `json:"ipv4"`
	IPv6     map[string]int `json:"ipv6"`
	Emails   map[string]int `json:"emails"`
	Hashes   map[string]int `json:"hashes"`
	Keywords map[string]int `json:"keywords"`
	PEHits   int            `json:"pe_hits"`
	Base64   []string       `json:"base64_sample"`
	Entropy  []EntropyPeak  `json:"entropy_peaks"`
}

type EntropyPeak struct {
	Offset  int64   `json:"offset"`
	Entropy float64 `json:"entropy"`
}

var (
	reURL    = regexp.MustCompile(`https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{6,}`)
	reIPv4   = regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b`)
	reIPv6   = regexp.MustCompile(`\b(?:[a-fA-F0-9]{1,4}:){2,7}[a-fA-F0-9]{1,4}\b`)
	reEmail  = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`)
	reHash   = regexp.MustCompile(`\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b`)
	reBase64 = regexp.MustCompile(`[A-Za-z0-9+/]{40,}={0,2}`)
)

var keywordIndex = []string{
	"mimikatz", "sekurlsa", "lsass", "cobaltstrike", "meterpreter",
	"powershell -enc", "invoke-expression", "downloadstring",
	"frombase64string", "reflection.assembly", "virtualalloc",
	"writeprocessmemory", "createremotethread", "ntcreatethreadex",
	"adjusttokenprivileges", "certutil -urlcache", "bitsadmin /transfer",
	"mshta http", "rundll32 javascript", "wscript.shell",
	"set-mppreference", "add-mppreference", "amsi",
	"keylogger", "getasynckeystate", "setwindowshookex",
	"ransom", "encryptor", "bitcoin", "monero", "onion", "socks5h",
}

const chunkSize = 1 << 20
const overlap = 32 * 1024

func Run(path string, opts Options) (*core.Result, error) {
	if opts.MinString < 1 {
		opts.MinString = 4
	}
	r := core.NewResult("memoryx", path)
	stat, err := os.Stat(path)
	if err != nil {
		return r, err
	}
	r.AddExtra("size", stat.Size())

	f, err := os.Open(path)
	if err != nil {
		return r, err
	}
	defer f.Close()

	iocs := IOCSet{
		URLs:     map[string]int{},
		IPv4:     map[string]int{},
		IPv6:     map[string]int{},
		Emails:   map[string]int{},
		Hashes:   map[string]int{},
		Keywords: map[string]int{},
	}

	hasher := sha256.New()
	br := bufio.NewReaderSize(f, chunkSize)
	buf := make([]byte, chunkSize)
	var carry []byte
	offset := int64(0)
	peaks := []EntropyPeak{}
	maxEntropy := 0.0

	for {
		n, rerr := io.ReadFull(br, buf)
		if n == 0 && rerr != nil {
			break
		}
		chunk := buf[:n]
		hasher.Write(chunk)

		combined := make([]byte, 0, len(carry)+len(chunk))
		combined = append(combined, carry...)
		combined = append(combined, chunk...)

		for i := 0; i+4096 <= len(chunk); i += 4096 {
			e := shannon(chunk[i : i+4096])
			if e > 7.5 && e > maxEntropy {
				maxEntropy = e
				peaks = append(peaks, EntropyPeak{Offset: offset + int64(i), Entropy: roundf(e, 3)})
				if len(peaks) > 100 {
					peaks = peaks[1:]
				}
			}
		}

		sweep(&iocs, combined)

		for i := 0; i+64 <= len(chunk); i++ {
			if chunk[i] == 'M' && chunk[i+1] == 'Z' {
				peOff := int(chunk[i+0x3C]) | int(chunk[i+0x3D])<<8 | int(chunk[i+0x3E])<<16 | int(chunk[i+0x3F])<<24
				if i+peOff+2 <= len(chunk) && chunk[i+peOff] == 'P' && chunk[i+peOff+1] == 'E' {
					iocs.PEHits++
				}
			}
		}

		if len(iocs.Base64) < 20 {
			for _, m := range reBase64.FindAll(combined, 20) {
				if len(iocs.Base64) >= 20 {
					break
				}
				decoded, err := base64.StdEncoding.DecodeString(string(m))
				if err == nil && len(decoded) > 8 {
					printable := 0
					for _, c := range decoded {
						if c >= 0x20 && c < 0x7f {
							printable++
						}
					}
					if float64(printable)/float64(len(decoded)) > 0.7 {
						iocs.Base64 = append(iocs.Base64, string(m))
					}
				}
			}
		}

		if len(combined) > overlap {
			carry = combined[len(combined)-overlap:]
		} else {
			carry = combined
		}
		offset += int64(n)
		if rerr != nil {
			break
		}
	}

	iocs.Entropy = peaks
	r.AddExtra("iocs", iocs)
	r.AddExtra("sha256", hex.EncodeToString(hasher.Sum(nil)))

	for u, n := range iocs.URLs {
		r.Add(core.Finding{Tool: "memoryx", Severity: core.SevInfo,
			Title: "URL", Detail: u, Evidence: map[string]any{"count": n}})
	}
	for kw, n := range iocs.Keywords {
		sev := core.SevMed
		if strings.Contains(kw, "mimikatz") || strings.Contains(kw, "cobaltstrike") ||
			strings.Contains(kw, "meterpreter") || strings.Contains(kw, "ransom") {
			sev = core.SevHigh
		}
		r.Add(core.Finding{Tool: "memoryx", Severity: sev,
			Title: "Keyword: " + kw, Evidence: map[string]any{"count": n}})
	}
	if iocs.PEHits > 0 {
		r.Add(core.Finding{Tool: "memoryx", Severity: core.SevMed,
			Title:  "Embedded PE headers in dump",
			Detail: intToString(iocs.PEHits)})
	}
	if maxEntropy > 7.5 {
		r.Add(core.Finding{Tool: "memoryx", Severity: core.SevMed,
			Title:  "High-entropy regions (packed/encrypted)",
			Detail: floatToString(maxEntropy)})
	}

	r.Finish()
	return r, nil
}

func sweep(iocs *IOCSet, data []byte) {
	for _, m := range reURL.FindAll(data, 200) {
		iocs.URLs[string(m)]++
	}
	for _, m := range reIPv4.FindAll(data, 200) {
		s := string(m)
		if s != "0.0.0.0" && s != "255.255.255.255" && s != "127.0.0.1" {
			iocs.IPv4[s]++
		}
	}
	for _, m := range reIPv6.FindAll(data, 100) {
		iocs.IPv6[string(m)]++
	}
	for _, m := range reEmail.FindAll(data, 200) {
		iocs.Emails[string(m)]++
	}
	for _, m := range reHash.FindAll(data, 200) {
		iocs.Hashes[strings.ToLower(string(m))]++
	}
	lower := bytes.ToLower(data)
	for _, kw := range keywordIndex {
		if bytes.Contains(lower, []byte(strings.ToLower(kw))) {
			iocs.Keywords[kw]++
		}
	}
}

func shannon(b []byte) float64 {
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

func intToString(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

func floatToString(f float64) string {
	return strings.TrimRight(strings.TrimRight(strings.Replace(
		formatFloat(f), ",", "", -1), "0"), ".")
}

func formatFloat(f float64) string {
	return strings.TrimSpace(itoa64(int64(f * 10000)))
}

func itoa64(n int64) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
