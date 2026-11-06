package cryptan

import (
	"fmt"
	"strings"

	core "github.com/brezzkin-dev/CINT/internal/cyber/core"
)

func BreakVigenere(ct string) *core.Result {
	r := core.NewResult("cryptan-vig", "")

	clean := strings.ToUpper(ct)
	var letters []rune
	for _, c := range clean {
		if c >= 'A' && c <= 'Z' {
			letters = append(letters, c)
		}
	}
	if len(letters) < 20 {
		r.Add(core.Finding{Tool: "cryptan", Severity: core.SevHigh,
			Title: "ciphertext too short for Vigenère analysis"})
		r.Finish()
		return r
	}

	type cand struct {
		length int
		ioc    float64
	}
	var cands []cand
	for L := 1; L <= 20; L++ {
		if L*10 > len(letters) {
			break
		}
		var iocSum float64
		for col := 0; col < L; col++ {
			var counts [26]int
			n := 0
			for i := col; i < len(letters); i += L {
				counts[letters[i]-'A']++
				n++
			}
			if n < 2 {
				continue
			}
			var num float64
			for _, c := range counts {
				num += float64(c * (c - 1))
			}
			den := float64(n * (n - 1))
			iocSum += num / den
		}
		iocSum /= float64(L)
		cands = append(cands, cand{length: L, ioc: iocSum})
	}

	bestLen := 1
	bestDist := 1.0
	for _, c := range cands {
		d := absf(c.ioc - 0.0667)
		if d < bestDist {
			bestDist = d
			bestLen = c.length
		}
	}
	r.AddExtra("key_length_estimate", bestLen)

	var key []rune
	for col := 0; col < bestLen; col++ {
		var counts [26]int
		for i := col; i < len(letters); i += bestLen {
			counts[letters[i]-'A']++
		}
		total := 0
		for _, c := range counts {
			total += c
		}
		bestShift := 0
		bestChi := 1e9
		for shift := 0; shift < 26; shift++ {
			var chi float64
			for i, obs := range counts {
				pt := (i - shift + 26) % 26
				exp := (englishFreq[rune('A'+pt)] / 100) * float64(total)
				if exp > 0 {
					d := float64(obs) - exp
					chi += d * d / exp
				}
			}
			if chi < bestChi {
				bestChi = chi
				bestShift = shift
			}
		}
		key = append(key, rune('A'+bestShift))
	}

	var pt []rune
	for i, c := range letters {
		k := key[i%len(key)] - 'A'
		pt = append(pt, rune((int(c-'A')-int(k)+26)%26)+'A')
	}

	r.AddExtra("key", string(key))
	r.AddExtra("plaintext_preview", previewRunes(pt))
	r.Add(core.Finding{
		Tool: "cryptan", Severity: core.SevHigh,
		Title:    "Vigenère key recovered",
		Detail:   fmt.Sprintf("key=%q len=%d", string(key), len(key)),
		Evidence: map[string]any{"key": string(key), "preview": previewRunes(pt)},
	})
	r.Finish()
	return r
}

func previewRunes(pt []rune) string {
	var b strings.Builder
	for i, c := range pt {
		if i >= 100 {
			b.WriteString("...")
			break
		}
		b.WriteRune(c)
	}
	return b.String()
}

func absf(f float64) float64 {
	if f < 0 {
		return -f
	}
	return f
}
