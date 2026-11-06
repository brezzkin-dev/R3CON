package t11_breachwatch

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	core "github.com/brezzkin-dev/CINT/internal/universe/core"
)

func Run(email, domain string) (*core.Result, error) {
	r := core.NewResult("breachwatch", firstNonEmpty(email, domain))
	ctx := context.Background()

	if email != "" {
		h := sha1.Sum([]byte(strings.ToLower(strings.TrimSpace(email))))
		hexStr := strings.ToUpper(hex.EncodeToString(h[:]))
		prefix := hexStr[:5]
		suffix := hexStr[5:]
		url := "https://api.pwnedpasswords.com/range/" + prefix
		status, _, body, err := core.HTTPGet(ctx, url, nil)
		if err == nil && status == 200 {
			count := 0
			for _, line := range strings.Split(string(body), "\r\n") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 && parts[0] == suffix {
					count, _ = strconv.Atoi(parts[1])
					break
				}
			}
			if count > 0 {
				r.Add(core.Finding{
					Tool: "breachwatch", Severity: core.SevHigh,
					Title:  "Email appears in Pwned Passwords",
					Detail: fmt.Sprintf("%d occurrences as password", count),
				})
			} else {
				r.Add(core.Finding{
					Tool: "breachwatch", Severity: core.SevInfo,
					Title: "Email not in Pwned Passwords corpus (as password)",
				})
			}
		} else {
			r.Add(core.Finding{Tool: "breachwatch", Severity: core.SevLow,
				Title: "HIBP lookup failed", Detail: fmt.Sprintf("status %d", status)})
		}
		r.AddExtra("note", "HIBP v3 account-breach API requires paid key — this checks password corpus only")
	}

	if domain != "" {
		url := "https://haveibeenpwned.com/api/v3/breaches"
		status, _, body, err := core.HTTPGet(ctx, url, map[string]string{"User-Agent": "CINT-OSINT"})
		if err == nil && status == 200 {
			bodyLower := strings.ToLower(string(body))
			if strings.Contains(bodyLower, `"domain":"`+strings.ToLower(domain)+`"`) {
				r.Add(core.Finding{
					Tool: "breachwatch", Severity: core.SevHigh,
					Title: "Domain appears in HIBP breach list", Detail: domain,
				})
			} else {
				r.Add(core.Finding{
					Tool: "breachwatch", Severity: core.SevInfo,
					Title: "Domain not in HIBP breach list",
				})
			}
		}
	}

	r.Finish()
	return r, nil
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}
