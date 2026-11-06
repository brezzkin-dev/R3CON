package t39_hashcrack

import (
	"bufio"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	core "github.com/brezzkin-dev/CINT/internal/universe/core"
)

func Run(hash, wordlist string, useRules bool) (*core.Result, error) {
	r := core.NewResult("hashcrack", hash)
	hash = strings.ToLower(strings.TrimSpace(hash))
	algo, ok := DetectAlgo(hash)
	if !ok {
		r.Add(core.Finding{Tool: "hashcrack", Severity: core.SevInfo,
			Title:  "unknown hash format",
			Detail: fmt.Sprintf("length %d, not matching MD5/SHA1/SHA256/SHA512", len(hash))})
		r.Finish()
		return r, nil
	}
	r.AddExtra("algo", algo)

	f, err := os.Open(wordlist)
	if err != nil {
		return r, fmt.Errorf("open wordlist: %w", err)
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 4096), 1<<20)
	var attempts int64
	var found string
	var matchedRule string

	for sc.Scan() {
		base := strings.TrimRight(sc.Text(), "\r\n")
		if base == "" {
			continue
		}
		candidates := []string{base}
		if useRules {
			candidates = append(candidates, Mutate(base)...)
		}
		for _, cand := range candidates {
			attempts++
			got := Hash(algo, []byte(cand))
			if subtle.ConstantTimeCompare([]byte(got), []byte(hash)) == 1 {
				found = cand
				if cand == base {
					matchedRule = "verbatim"
				} else {
					matchedRule = "mutated"
				}
				goto done
			}
			if attempts >= 50_000_000 {
				goto done
			}
		}
	}

done:
	r.AddExtra("attempts", attempts)
	if found != "" {
		r.AddExtra("plaintext", found)
		r.AddExtra("matched_rule", matchedRule)
		r.Add(core.Finding{
			Tool: "hashcrack", Severity: core.SevHigh,
			Title:  "hash cracked",
			Detail: fmt.Sprintf("%q (after %d attempts)", found, attempts),
			Evidence: map[string]any{
				"algo": algo, "plaintext": found, "attempts": attempts,
			},
		})
	} else {
		r.Add(core.Finding{Tool: "hashcrack", Severity: core.SevInfo,
			Title:  "hash NOT cracked",
			Detail: fmt.Sprintf("%d attempts, no match", attempts)})
	}
	r.Finish()
	return r, nil
}

func DetectAlgo(hash string) (string, bool) {
	if !isHex(hash) {
		return "", false
	}
	switch len(hash) {
	case 32:
		return "MD5", true
	case 40:
		return "SHA1", true
	case 64:
		return "SHA256", true
	case 128:
		return "SHA512", true
	}
	return "", false
}

func isHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func Hash(algo string, plaintext []byte) string {
	switch algo {
	case "MD5":
		h := md5.Sum(plaintext)
		return hex.EncodeToString(h[:])
	case "SHA1":
		h := sha1.Sum(plaintext)
		return hex.EncodeToString(h[:])
	case "SHA256":
		h := sha256.Sum256(plaintext)
		return hex.EncodeToString(h[:])
	case "SHA512":
		h := sha512.Sum512(plaintext)
		return hex.EncodeToString(h[:])
	}
	return ""
}

func Mutate(word string) []string {
	var out []string
	out = append(out, strings.ToLower(word))
	out = append(out, strings.ToUpper(word))
	if len(word) > 0 {
		out = append(out, strings.ToUpper(word[:1])+strings.ToLower(word[1:]))
	}
	for i := 0; i <= 99; i++ {
		out = append(out, fmt.Sprintf("%s%d", word, i))
	}
	for _, s := range []string{"!", "!!", "!!!", "@", "#", "$", "123", "1234", "2024", "2025", "2026"} {
		out = append(out, word+s)
	}
	out = append(out, leetVariants(word)...)
	return out
}

func leetVariants(word string) []string {
	subs := map[byte][]byte{
		'a': {'@', '4'},
		'e': {'3'},
		'i': {'1', '!'},
		'o': {'0'},
		's': {'5', '$'},
		't': {'7'},
	}
	lower := strings.ToLower(word)
	var results []string
	for i := 0; i < len(lower) && i < 20; i++ {
		subsForChar, ok := subs[lower[i]]
		if !ok {
			continue
		}
		for _, sub := range subsForChar {
			mutated := []byte(lower)
			mutated[i] = sub
			results = append(results, string(mutated))
		}
	}
	if len(lower) <= 12 {
		allLeet := make([]byte, len(lower))
		changed := false
		for i := 0; i < len(lower); i++ {
			if subsForChar, ok := subs[lower[i]]; ok && len(subsForChar) > 0 {
				allLeet[i] = subsForChar[0]
				changed = true
			} else {
				allLeet[i] = lower[i]
			}
		}
		if changed {
			results = append(results, string(allLeet))
		}
	}
	return results
}
