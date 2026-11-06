package wsa

import (
	"context"
	"crypto/tls"
	"net"
	"net/url"
	"sort"
	"strings"
	"time"

	core "github.com/brezzkin-dev/CINT/internal/cyber/core"
)

type Options struct {
	Inject   bool
	Takeover bool
}

var secHeaders = map[string]struct {
	Sev core.Severity
	Msg string
}{
	"Strict-Transport-Security": {core.SevHigh, "HSTS missing"},
	"Content-Security-Policy":   {core.SevMed, "CSP missing"},
	"X-Frame-Options":           {core.SevMed, "clickjacking possible"},
	"X-Content-Type-Options":    {core.SevLow, "MIME sniffing possible"},
	"Referrer-Policy":           {core.SevLow, "referrer leakage"},
	"Permissions-Policy":        {core.SevLow, "browser feature access unrestricted"},
}

var wafSigs = map[string][]string{
	"Cloudflare":  {"cloudflare", "cf-ray"},
	"Akamai":      {"akamai", "akamaighost"},
	"AWS WAF":     {"awselb", "x-amz-cf-id"},
	"Imperva":     {"incap_ses", "visid_incap"},
	"F5 BIG-IP":   {"bigipserver", "x-wa-info"},
	"Sucuri":      {"sucuri", "x-sucuri-id"},
	"ModSecurity": {"mod_security", "modsecurity"},
}

func auditTLS(host string) *tls.ConnectionState {
	cfg := &tls.Config{InsecureSkipVerify: true, ServerName: host}
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", host+":443", cfg)
	if err != nil {
		return nil
	}
	defer conn.Close()
	st := conn.ConnectionState()
	return &st
}

func Audit(ctx context.Context, target string, opts Options) *core.Result {
	r := core.NewResult("wsa", target)
	if !strings.HasPrefix(target, "http") {
		target = "https://" + target
	}
	u, err := url.Parse(target)
	if err != nil {
		r.Add(core.Finding{Tool: "wsa", Severity: core.SevHigh, Title: "invalid URL", Detail: err.Error()})
		r.Finish()
		return r
	}

	status, headers, body, err := core.HTTPGet(ctx, target, nil)
	if err != nil {
		r.Add(core.Finding{Tool: "wsa", Severity: core.SevHigh, Title: "fetch failed", Detail: err.Error()})
		r.Finish()
		return r
	}
	r.AddExtra("status", status)
	r.AddExtra("body_size", len(body))

	lcHeaders := map[string]string{}
	for k, v := range headers {
		lcHeaders[strings.ToLower(k)] = strings.Join(v, ", ")
	}

	for name, cfg := range secHeaders {
		if _, ok := lcHeaders[strings.ToLower(name)]; !ok {
			r.Add(core.Finding{Tool: "wsa", Severity: cfg.Sev,
				Title: "Missing header: " + name, Detail: cfg.Msg})
		}
	}

	for waf, sigs := range wafSigs {
		for _, sig := range sigs {
			if strings.Contains(strings.ToLower(fmtHeaders(headers)), sig) {
				r.AddExtra("waf", waf)
				break
			}
		}
	}

	for _, cookie := range headers["Set-Cookie"] {
		lc := strings.ToLower(cookie)
		if !strings.Contains(lc, "secure") && u.Scheme == "https" {
			r.Add(core.Finding{Tool: "wsa", Severity: core.SevMed, Title: "Cookie missing Secure"})
		}
		if !strings.Contains(lc, "httponly") {
			r.Add(core.Finding{Tool: "wsa", Severity: core.SevMed, Title: "Cookie missing HttpOnly"})
		}
		if !strings.Contains(lc, "samesite") {
			r.Add(core.Finding{Tool: "wsa", Severity: core.SevLow, Title: "Cookie missing SameSite"})
		}
	}

	if state := auditTLS(u.Hostname()); state != nil {
		r.AddExtra("tls_version", tlsVersionString(state.Version))
		r.AddExtra("cipher_suite", tls.CipherSuiteName(state.CipherSuite))
		r.AddExtra("tls_verified", false)
		if state.Version < tls.VersionTLS12 {
			r.Add(core.Finding{Tool: "wsa", Severity: core.SevHigh,
				Title: "Weak TLS: " + tlsVersionString(state.Version)})
		}
		if len(state.PeerCertificates) > 0 {
			cert := state.PeerCertificates[0]
			r.AddExtra("cert_subject", cert.Subject.String())
			r.AddExtra("cert_issuer", cert.Issuer.String())
			r.AddExtra("cert_expires", cert.NotAfter.Format(time.RFC3339))
			if time.Now().After(cert.NotAfter) {
				r.Add(core.Finding{Tool: "wsa", Severity: core.SevCrit, Title: "Certificate expired"})
			}
		}
	}

	if opts.Inject {
		runInjectionProbes(ctx, u, r)
	}
	if opts.Takeover {
		checkTakeover(u.Hostname(), r)
	}

	r.Finish()
	return r
}

func fmtHeaders(h map[string][]string) string {
	var b strings.Builder
	for k, v := range h {
		b.WriteString(k)
		b.WriteString(": ")
		b.WriteString(strings.Join(v, ", "))
		b.WriteString("\n")
	}
	return b.String()
}

func tlsVersionString(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	}
	return "unknown"
}

var _ = sort.Strings
