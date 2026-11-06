package t13_certtrace

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	core "github.com/brezzkin-dev/CINT/internal/universe/core"
)

func Run(domain string) (*core.Result, error) {
	r := core.NewResult("certtrace", domain)
	ctx := context.Background()

	// InsecureSkipVerify is intentional here — this tool inspects the
	// certificate, it does not establish a trusted connection. The result
	// carries tls_verified=false so callers know not to treat the
	// connection as authenticated.
	cfg := &tls.Config{ServerName: domain, InsecureSkipVerify: true}
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", domain+":443", cfg)
	if err == nil {
		state := conn.ConnectionState()
		conn.Close()
		r.AddExtra("tls_version", tlsVersionStr(state.Version))
		r.AddExtra("cipher_suite", tls.CipherSuiteName(state.CipherSuite))
		r.AddExtra("tls_verified", false)
		if len(state.PeerCertificates) > 0 {
			c := state.PeerCertificates[0]
			certInfo := map[string]any{
				"subject":    c.Subject.String(),
				"issuer":     c.Issuer.String(),
				"not_before": c.NotBefore.Format(time.RFC3339),
				"not_after":  c.NotAfter.Format(time.RFC3339),
				"serial":     c.SerialNumber.String(),
				"dns_names":  c.DNSNames,
				"is_ca":      c.IsCA,
				"sig_algo":   c.SignatureAlgorithm.String(),
			}
			r.AddExtra("live_cert", certInfo)
			if time.Now().After(c.NotAfter) {
				r.Add(core.Finding{Tool: "certtrace", Severity: core.SevCrit,
					Title: "Live certificate expired", Detail: c.NotAfter.String()})
			} else if time.Now().Add(30 * 24 * time.Hour).After(c.NotAfter) {
				r.Add(core.Finding{Tool: "certtrace", Severity: core.SevMed,
					Title: "Certificate expires within 30 days", Detail: c.NotAfter.String()})
			}
			for _, name := range c.DNSNames {
				if strings.HasPrefix(name, "*.") {
					r.AddExtra("wildcard_cert", true)
					break
				}
			}
		}
	} else {
		r.Add(core.Finding{Tool: "certtrace", Severity: core.SevLow,
			Title: "TLS connect failed", Detail: err.Error()})
	}

	if err := queryCT(ctx, domain, r); err != nil {
		core.Debugf("ct: %v", err)
	}

	r.Finish()
	return r, nil
}

func queryCT(ctx context.Context, domain string, r *core.Result) error {
	url := fmt.Sprintf("https://crt.sh/?q=%s&output=json", domain)
	status, _, body, err := core.HTTPGet(ctx, url, nil)
	if err != nil || status != 200 {
		return fmt.Errorf("crt.sh http %d", status)
	}
	var certs []struct {
		IssuerCAID   int    `json:"issuer_ca_id"`
		IssuerName   string `json:"issuer_name"`
		CommonName   string `json:"common_name"`
		NameValue    string `json:"name_value"`
		NotBefore    string `json:"not_before"`
		NotAfter     string `json:"not_after"`
		SerialNumber string `json:"serial_number"`
	}
	if json.Unmarshal(body, &certs) != nil {
		return err
	}
	r.AddExtra("ct_history_count", len(certs))

	issuers := map[string]int{}
	for _, c := range certs {
		issuers[c.IssuerName]++
	}
	r.AddExtra("ct_issuers", issuers)

	wildcards := map[string]bool{}
	for _, c := range certs {
		for _, line := range strings.Split(c.NameValue, "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "*.") {
				wildcards[line] = true
			}
		}
	}
	var wc []string
	for w := range wildcards {
		wc = append(wc, w)
	}
	r.AddExtra("wildcard_names", wc)

	if len(certs) > 0 {
		latest := certs[0]
		for _, c := range certs {
			if c.NotBefore > latest.NotBefore {
				latest = c
			}
		}
		r.AddExtra("latest_ct_cert", latest)
	}
	return nil
}

func tlsVersionStr(v uint16) string {
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
