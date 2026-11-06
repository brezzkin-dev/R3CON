package t35_certnexus

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	core "github.com/brezzkin-dev/CINT/internal/universe/core"
)

const crtDomainURL = "https://crt.sh/?q=%s&output=json"

type liveCert struct {
	Subject     string   `json:"subject"`
	Issuer      string   `json:"issuer"`
	IssuerCN    string   `json:"issuer_cn"`
	NotBefore   string   `json:"not_before"`
	NotAfter    string   `json:"not_after"`
	Serial      string   `json:"serial"`
	DNSNames    []string `json:"dns_names"`
	IsWildcard  bool     `json:"is_wildcard"`
	SigAlgo     string   `json:"sig_algo"`
	KeyAlgo     string   `json:"key_algo"`
	TLSVersion  string   `json:"tls_version"`
	CipherSuite string   `json:"cipher_suite"`
	Verified    bool     `json:"tls_verified"`
	ChainLen    int      `json:"chain_len"`
}

type ctCert struct {
	ID         int64  `json:"id"`
	IssuerCAID int    `json:"issuer_ca_id"`
	IssuerName string `json:"issuer_name"`
	CommonName string `json:"common_name"`
	NameValue  string `json:"name_value"`
	NotBefore  string `json:"not_before"`
	NotAfter   string `json:"not_after"`
	Serial     string `json:"serial_number"`
}

func Run(domain string) (*core.Result, error) {
	r := core.NewResult("certnexus", domain)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	live := grabLiveCert(domain)
	r.AddExtra("live_cert", live)
	if live != nil {
		if !live.Verified {
			r.Add(core.Finding{Tool: "certnexus", Severity: core.SevMed,
				Title:  "TLS cert verification NOT confirmed",
				Detail: "connection used InsecureSkipVerify — inspect chain manually"})
		}
		expiry, err := time.Parse(time.RFC3339, live.NotAfter)
		if err == nil {
			days := int(time.Until(expiry).Hours() / 24)
			r.AddExtra("days_until_expiry", days)
			if days < 0 {
				r.Add(core.Finding{Tool: "certnexus", Severity: core.SevCrit,
					Title: "Certificate EXPIRED", Detail: live.NotAfter})
			} else if days < 30 {
				r.Add(core.Finding{Tool: "certnexus", Severity: core.SevMed,
					Title:  fmt.Sprintf("Certificate expires in %d days", days),
					Detail: live.NotAfter})
			}
		}
		if live.IsWildcard {
			r.AddExtra("wildcard", true)
			r.Add(core.Finding{Tool: "certnexus", Severity: core.SevLow,
				Title: "Wildcard certificate"})
		}
		if live.SigAlgo == "SHA1-RSA" || strings.Contains(live.SigAlgo, "MD5") {
			r.Add(core.Finding{Tool: "certnexus", Severity: core.SevHigh,
				Title: "Weak signature algorithm: " + live.SigAlgo})
		}
	}

	ct, err := fetchCT(ctx, domain)
	if err != nil {
		core.Debugf("ct: %v", err)
	} else {
		r.AddExtra("ct_count", len(ct))

		issuers := map[string]int{}
		for _, c := range ct {
			issuers[c.IssuerName]++
		}
		r.AddExtra("ct_issuers", mapToSorted(issuers))

		sans := map[string]bool{}
		wildcards := map[string]bool{}
		for _, c := range ct {
			for _, line := range strings.Split(c.NameValue, "\n") {
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}
				if strings.HasPrefix(line, "*.") {
					wildcards[line] = true
				}
				if line != domain && strings.HasSuffix(line, "."+domain) {
					sans[line] = true
				}
			}
		}
		r.AddExtra("subdomains_from_ct", mapKeys(sans, 300))
		r.AddExtra("wildcards_from_ct", mapKeys(wildcards, 50))

		sort.Slice(ct, func(i, j int) bool { return ct[i].NotBefore > ct[j].NotBefore })
		if len(ct) > 0 {
			latest := ct[0]
			r.AddExtra("latest_ct", map[string]any{
				"common_name": latest.CommonName,
				"issuer":      latest.IssuerName,
				"not_before":  latest.NotBefore,
				"not_after":   latest.NotAfter,
			})
		}

		if len(issuers) > 1 {
			r.Add(core.Finding{
				Tool: "certnexus", Severity: core.SevInfo,
				Title:  fmt.Sprintf("%d CAs issued certs for this domain", len(issuers)),
				Detail: strings.Join(mapIntKeys(issuers, 10), ", "),
			})
		}
	}

	r.Finish()
	return r, nil
}

func grabLiveCert(domain string) *liveCert {
	cfg := &tls.Config{ServerName: domain, InsecureSkipVerify: true}
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", domain+":443", cfg)
	if err != nil {
		return nil
	}
	defer conn.Close()
	st := conn.ConnectionState()

	out := &liveCert{
		TLSVersion:  tlsVersionStr(st.Version),
		CipherSuite: tls.CipherSuiteName(st.CipherSuite),
		ChainLen:    len(st.PeerCertificates),
		Verified:    len(st.VerifiedChains) > 0,
	}
	if len(st.PeerCertificates) == 0 {
		return out
	}
	c := st.PeerCertificates[0]
	out.Subject = c.Subject.String()
	out.Issuer = c.Issuer.String()
	out.IssuerCN = c.Issuer.CommonName
	out.NotBefore = c.NotBefore.Format(time.RFC3339)
	out.NotAfter = c.NotAfter.Format(time.RFC3339)
	out.Serial = c.SerialNumber.String()
	out.DNSNames = c.DNSNames
	out.SigAlgo = c.SignatureAlgorithm.String()
	out.KeyAlgo = c.PublicKeyAlgorithm.String()
	for _, n := range c.DNSNames {
		if strings.HasPrefix(n, "*.") {
			out.IsWildcard = true
			break
		}
	}
	return out
}

func fetchCT(ctx context.Context, domain string) ([]ctCert, error) {
	url := fmt.Sprintf(crtDomainURL, domain)
	status, _, body, err := core.HTTPGet(ctx, url, nil)
	if err != nil || status != 200 {
		return nil, fmt.Errorf("crt.sh http %d", status)
	}
	var raw []ctCert
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, err
	}
	if len(raw) > 1000 {
		raw = raw[:1000]
	}
	return raw, nil
}

func mapToSorted(m map[string]int) []map[string]any {
	type kv struct {
		k string
		v int
	}
	var arr []kv
	for k, v := range m {
		arr = append(arr, kv{k, v})
	}
	sort.Slice(arr, func(i, j int) bool { return arr[i].v > arr[j].v })
	out := make([]map[string]any, len(arr))
	for i, e := range arr {
		out[i] = map[string]any{"name": e.k, "count": e.v}
	}
	return out
}

func mapKeys(m map[string]bool, limit int) []string {
	var out []string
	for k := range m {
		out = append(out, k)
		if len(out) >= limit {
			break
		}
	}
	sort.Strings(out)
	return out
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
	return fmt.Sprintf("unknown(0x%04x)", v)
}

func mapIntKeys(m map[string]int, limit int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if limit > 0 && len(keys) > limit {
		keys = keys[:limit]
	}
	return keys
}
