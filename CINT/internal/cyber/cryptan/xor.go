package cryptan

import (
	"fmt"

	core "github.com/brezzkin-dev/CINT/internal/cyber/core"
)

func BreakXOR(ct []byte) *core.Result {
	r := core.NewResult("cryptan-xor", "")
	r.AddExtra("ciphertext_len", len(ct))

	type scored struct {
		key     byte
		plain   []byte
		chi     float64
		preview string
	}

	var best []scored
	for k := 0; k < 256; k++ {
		pt := make([]byte, len(ct))
		for i, b := range ct {
			pt[i] = b ^ byte(k)
		}
		chi := scoreEnglish(pt)
		preview := ""
		for _, b := range pt {
			if b >= 0x20 && b < 0x7f {
				preview += string(b)
			} else if b == '\n' || b == '\t' {
				preview += string(b)
			} else {
				preview += "."
			}
		}
		if len(preview) > 80 {
			preview = preview[:80] + "..."
		}
		best = append(best, scored{key: byte(k), plain: pt, chi: chi, preview: preview})
	}

	for i := 1; i < len(best); i++ {
		for j := i; j > 0 && best[j].chi < best[j-1].chi; j-- {
			best[j], best[j-1] = best[j-1], best[j]
		}
	}

	if len(best) > 0 {
		top := best[:minInt5(5, len(best))]
		results := make([]map[string]any, len(top))
		for i, b := range top {
			results[i] = map[string]any{
				"key":               fmt.Sprintf("0x%02x", b.key),
				"chi":               b.chi,
				"plaintext_preview": b.preview,
			}
		}
		r.AddExtra("top_candidates", results)
		top1 := top[0]
		r.Add(core.Finding{
			Tool: "cryptan", Severity: core.SevHigh,
			Title:  "XOR key recovered",
			Detail: fmt.Sprintf("key=0x%02x chi=%.2f", top1.key, top1.chi),
			Evidence: map[string]any{
				"key_hex":   fmt.Sprintf("%02x", top1.key),
				"plaintext": string(top1.plain),
			},
		})
	}
	r.Finish()
	return r
}

func scoreEnglish(b []byte) float64 {
	var counts [26]int
	total := 0
	for _, c := range b {
		u := c
		if u >= 'a' && u <= 'z' {
			u -= 32
		}
		if u >= 'A' && u <= 'Z' {
			counts[u-'A']++
			total++
		}
	}
	if total == 0 {
		return 1e9
	}
	var chi float64
	for c := 'A'; c <= 'Z'; c++ {
		expFrac := englishFreq[c] / 100
		expCount := expFrac * float64(total)
		obs := float64(counts[c-'A'])
		if expCount > 0 {
			d := obs - expCount
			chi += d * d / expCount
		}
	}
	nonPrintable := 0
	for _, c := range b {
		if (c < 0x20 && c != '\n' && c != '\t' && c != '\r') || c > 0x7e {
			nonPrintable++
		}
	}
	chi += float64(nonPrintable) * 50
	return chi
}

func minInt5(a, b int) int {
	if a < b {
		return a
	}
	return b
}
