package cryptan

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	core "github.com/brezzkin-dev/CINT/internal/cyber/core"
)

func IdentifyHash(h string) (string, string) {
	h = strings.TrimSpace(h)
	switch {
	case len(h) == 32 && isHex(h):
		return "MD5", "fast"
	case len(h) == 40 && isHex(h):
		return "SHA1", "fast"
	case len(h) == 64 && isHex(h):
		return "SHA256", "medium"
	case len(h) == 128 && isHex(h):
		return "SHA512", "medium"
	case strings.HasPrefix(h, "$2a$") || strings.HasPrefix(h, "$2b$") || strings.HasPrefix(h, "$2y$"):
		return "bcrypt", "slow"
	case strings.HasPrefix(h, "$argon2"):
		return "argon2", "slow"
	case strings.HasPrefix(h, "$1$"):
		return "MD5-crypt", "fast"
	case strings.HasPrefix(h, "$5$"):
		return "SHA256-crypt", "medium"
	case strings.HasPrefix(h, "$6$"):
		return "SHA512-crypt", "medium"
	}
	return "unknown", "unknown"
}

func isHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func computeHash(algo string, s []byte) string {
	switch algo {
	case "MD5":
		h := md5.Sum(s)
		return hex.EncodeToString(h[:])
	case "SHA1":
		h := sha1.Sum(s)
		return hex.EncodeToString(h[:])
	case "SHA256":
		h := sha256.Sum256(s)
		return hex.EncodeToString(h[:])
	case "SHA512":
		h := sha512.Sum512(s)
		return hex.EncodeToString(h[:])
	}
	return ""
}

func IDResult(h string) *core.Result {
	r := core.NewResult("cryptan-id", h)
	algo, speed := IdentifyHash(h)
	r.AddExtra("algo", algo)
	r.AddExtra("speed", speed)
	r.Finish()
	return r
}

func Crack(hash string, wordlistPath string) *core.Result {
	r := core.NewResult("cryptan-crack", hash)
	algo, _ := IdentifyHash(hash)
	r.AddExtra("algo", algo)
	if algo == "unknown" {
		r.Add(core.Finding{Tool: "cryptan", Severity: core.SevMed, Title: "unknown hash format"})
		r.Finish()
		return r
	}
	f, err := os.Open(wordlistPath)
	if err != nil {
		r.Add(core.Finding{Tool: "cryptan", Severity: core.SevHigh,
			Title: "wordlist not readable", Detail: err.Error()})
		r.Finish()
		return r
	}
	defer f.Close()
	target := strings.ToLower(hash)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024), 1024*1024)
	var tried int
	for sc.Scan() {
		word := strings.TrimRight(sc.Text(), "\r\n")
		tried++
		h := computeHash(algo, []byte(word))
		if subtle.ConstantTimeCompare([]byte(h), []byte(target)) == 1 {
			r.Add(core.Finding{
				Tool: "cryptan", Severity: core.SevHigh,
				Title:    "hash cracked",
				Detail:   fmt.Sprintf("%q (%d attempts)", word, tried),
				Evidence: map[string]any{"plaintext": word, "attempts": tried},
			})
			r.Finish()
			return r
		}
	}
	r.AddExtra("attempts", tried)
	r.Finish()
	return r
}

func DecodeJWT(token string) *core.Result {
	r := core.NewResult("cryptan-jwt", "")
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		r.Add(core.Finding{Tool: "cryptan", Severity: core.SevHigh, Title: "not a JWT"})
		r.Finish()
		return r
	}
	hdr, err1 := base64.RawURLEncoding.DecodeString(parts[0])
	body, err2 := base64.RawURLEncoding.DecodeString(parts[1])
	sig, err3 := base64.RawURLEncoding.DecodeString(parts[2])
	if err1 != nil || err2 != nil || err3 != nil {
		r.Add(core.Finding{Tool: "cryptan", Severity: core.SevHigh, Title: "decode error"})
		r.Finish()
		return r
	}
	var hdrObj, bodyObj map[string]any
	json.Unmarshal(hdr, &hdrObj)
	json.Unmarshal(body, &bodyObj)
	r.AddExtra("header", hdrObj)
	r.AddExtra("payload", bodyObj)
	r.AddExtra("signature_hex", hex.EncodeToString(sig))
	if alg, ok := hdrObj["alg"].(string); ok {
		switch alg {
		case "none":
			r.Add(core.Finding{Tool: "cryptan", Severity: core.SevCrit, Title: "alg=none — unsigned JWT"})
		case "HS256", "HS384", "HS512":
			r.Add(core.Finding{Tool: "cryptan", Severity: core.SevMed, Title: "HMAC-signed JWT"})
		}
	}
	r.Finish()
	return r
}

func AESCrypt(encrypt bool, keyHex, inputPath, outputPath string) error {
	key, err := hex.DecodeString(keyHex)
	if err != nil || (len(key) != 16 && len(key) != 24 && len(key) != 32) {
		return fmt.Errorf("key must be 16/24/32 bytes hex")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	input, err := os.ReadFile(inputPath)
	if err != nil {
		return err
	}
	if encrypt {
		nonce := make([]byte, gcm.NonceSize())
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			return err
		}
		out := gcm.Seal(nonce, nonce, input, nil)
		return os.WriteFile(outputPath, out, 0644)
	}
	ns := gcm.NonceSize()
	if len(input) < ns {
		return fmt.Errorf("ciphertext too short")
	}
	nonce, ct := input[:ns], input[ns:]
	plain, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return err
	}
	return os.WriteFile(outputPath, plain, 0644)
}

var englishFreq = map[rune]float64{
	'A': 8.17, 'B': 1.49, 'C': 2.78, 'D': 4.25, 'E': 12.70, 'F': 2.23,
	'G': 2.02, 'H': 6.09, 'I': 6.97, 'J': 0.15, 'K': 0.77, 'L': 4.03,
	'M': 2.41, 'N': 6.75, 'O': 7.51, 'P': 1.93, 'Q': 0.10, 'R': 5.99,
	'S': 6.33, 'T': 9.06, 'U': 2.76, 'V': 0.98, 'W': 2.36, 'X': 0.15,
	'Y': 1.97, 'Z': 0.07,
}

func FreqAnalysis(s string) *core.Result {
	r := core.NewResult("cryptan-freq", "")
	counts := map[rune]int{}
	total := 0
	for _, c := range strings.ToUpper(s) {
		if c >= 'A' && c <= 'Z' {
			counts[c]++
			total++
		}
	}
	if total == 0 {
		r.Add(core.Finding{Tool: "cryptan", Severity: core.SevHigh, Title: "no alphabetic content"})
		r.Finish()
		return r
	}
	freq := map[string]float64{}
	for k, v := range counts {
		freq[string(k)] = float64(v) / float64(total) * 100
	}
	r.AddExtra("total_letters", total)
	r.AddExtra("frequency_pct", freq)
	var chi float64
	for c := 'A'; c <= 'Z'; c++ {
		exp := englishFreq[c] / 100 * float64(total)
		obs := float64(counts[c])
		if exp > 0 {
			chi += (obs - exp) * (obs - exp) / exp
		}
	}
	r.AddExtra("chi_square", chi)
	if chi < 50 {
		r.Add(core.Finding{Tool: "cryptan", Severity: core.SevInfo,
			Title: "likely English plaintext", Detail: fmt.Sprintf("chi %.2f", chi)})
	} else {
		r.Add(core.Finding{Tool: "cryptan", Severity: core.SevMed,
			Title: "unlikely English", Detail: fmt.Sprintf("chi %.2f", chi)})
	}
	r.Finish()
	return r
}
