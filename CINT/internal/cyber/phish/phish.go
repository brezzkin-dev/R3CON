package phish

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"

	core "github.com/brezzkin-dev/CINT/internal/cyber/core"
)

var suspiciousTLDs = []string{
	".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".cc",
	".click", ".download", ".loan", ".work", ".gdn",
}

var brandWords = []string{
	"paypal", "apple", "microsoft", "google", "amazon", "facebook",
	"instagram", "netflix", "dhl", "fedex", "ups", "steam", "binance",
	"coinbase", "metamask", "revolut", "hsbc", "chase",
}

func hasNonASCII(s string) bool {
	for _, c := range s {
		if c > unicode.MaxASCII {
			return true
		}
	}
	return false
}

func lexicalScore(u *url.URL) (int, []string) {
	var score int
	var reasons []string
	host := strings.ToLower(u.Hostname())

	if hasNonASCII(host) {
		score += 30
		reasons = append(reasons, "non-ASCII hostname (homograph)")
	}
	if strings.Contains(host, "xn--") {
		score += 25
		reasons = append(reasons, "punycode hostname")
	}
	for _, tld := range suspiciousTLDs {
		if strings.HasSuffix(host, tld) {
			score += 15
			reasons = append(reasons, "suspicious TLD "+tld)
			break
		}
	}
	for _, b := range brandWords {
		if strings.Contains(host, b) && !isLegitBrand(u.Hostname(), b) {
			score += 30
			reasons = append(reasons, "brand mimicry: "+b)
			break
		}
	}
	if len(host) > 30 {
		score += 10
		reasons = append(reasons, "long hostname")
	}
	if strings.Count(host, ".") > 4 {
		score += 15
		reasons = append(reasons, "excessive subdomains")
	}
	if strings.Contains(u.Path, "@") {
		score += 20
		reasons = append(reasons, "@ in URL path")
	}
	return score, reasons
}

func isLegitBrand(host, brand string) bool {
	return host == brand+".com" || host == "www."+brand+".com"
}

func checkDNS(ctx context.Context, domain string, r *core.Result) {
	txts, _ := net.DefaultResolver.LookupTXT(ctx, domain)
	var spf, dmarc bool
	for _, t := range txts {
		if strings.HasPrefix(t, "v=spf1") {
			spf = true
		}
	}
	dmarcs, _ := net.DefaultResolver.LookupTXT(ctx, "_dmarc."+domain)
	for _, t := range dmarcs {
		if strings.HasPrefix(t, "v=DMARC1") {
			dmarc = true
		}
	}
	r.AddExtra("spf", spf)
	r.AddExtra("dmarc", dmarc)
	if !spf {
		r.Add(core.Finding{Tool: "phish", Severity: core.SevMed,
			Title: "SPF missing", Detail: domain})
	}
	if !dmarc {
		r.Add(core.Finding{Tool: "phish", Severity: core.SevMed,
			Title: "DMARC missing", Detail: domain})
	}
}

func Analyze(ctx context.Context, raw string) *core.Result {
	r := core.NewResult("phish", raw)
	if !strings.HasPrefix(raw, "http") {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		r.Add(core.Finding{Tool: "phish", Severity: core.SevHigh,
			Title: "invalid URL", Detail: err.Error()})
		r.Finish()
		return r
	}
	score, reasons := lexicalScore(u)
	r.AddExtra("host", u.Hostname())
	r.AddExtra("score", score)
	r.AddExtra("reasons", reasons)

	checkDNS(ctx, u.Hostname(), r)

	if score >= 60 {
		r.Add(core.Finding{Tool: "phish", Severity: core.SevCrit,
			Title:  "high phishing likelihood",
			Detail: strings.Join(reasons, ", ")})
	} else if score >= 30 {
		r.Add(core.Finding{Tool: "phish", Severity: core.SevHigh,
			Title: "suspicious", Detail: strings.Join(reasons, ", ")})
	}
	r.Finish()
	return r
}

var _ = http.MethodGet
var _ = fmt.Sprintf
var _ = time.Now
