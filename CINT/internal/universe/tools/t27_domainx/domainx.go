package t27_domainx

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	core "github.com/brezzkin-dev/CINT/internal/universe/core"
)

func Run(domain string) (*core.Result, error) {
	r := core.NewResult("domainx", domain)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	resolver := pickResolver()

	if ips, err := net.LookupHost(domain); err == nil {
		var v4, v6 []string
		for _, ip := range ips {
			if strings.Contains(ip, ":") {
				v6 = append(v6, ip)
			} else {
				v4 = append(v4, ip)
			}
		}
		r.AddExtra("a", v4)
		r.AddExtra("aaaa", v6)
	}

	if cname, err := net.LookupCNAME(domain); err == nil && cname != domain+"." {
		r.AddExtra("cname", strings.TrimSuffix(cname, "."))
	}

	if mxs, err := net.LookupMX(domain); err == nil {
		out := make([]map[string]any, 0, len(mxs))
		for _, m := range mxs {
			out = append(out, map[string]any{
				"host": strings.TrimSuffix(m.Host, "."),
				"pref": m.Pref,
			})
		}
		r.AddExtra("mx", out)
		go reverseMX(ctx, mxs, r)
	}

	if nss, err := net.LookupNS(domain); err == nil {
		out := make([]string, 0, len(nss))
		for _, ns := range nss {
			out = append(out, strings.TrimSuffix(ns.Host, "."))
		}
		r.AddExtra("ns", out)
	}

	if txts, err := net.LookupTXT(domain); err == nil {
		r.AddExtra("txt", txts)
		for _, t := range txts {
			if strings.HasPrefix(t, "v=spf1") {
				r.AddExtra("spf", t)
			}
		}
	}

	if dmarcs, err := net.LookupTXT("_dmarc." + domain); err == nil {
		for _, t := range dmarcs {
			if strings.HasPrefix(t, "v=DMARC1") {
				r.AddExtra("dmarc", t)
			}
		}
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if ans, err := queryDNS(resolver, domain, dnsTypeSOA, 5*time.Second); err == nil {
			for _, a := range ans {
				if a.Type == dnsTypeSOA {
					if soa := parseSOA(a.RDATA); soa != nil {
						r.AddExtra("soa", soa)
					}
				}
			}
		}
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		if ans, err := queryDNS(resolver, domain, dnsTypeCAA, 5*time.Second); err == nil {
			var caa []map[string]any
			for _, a := range ans {
				if a.Type == dnsTypeCAA {
					if c := parseCAA(a.RDATA); c != nil {
						caa = append(caa, c)
					}
				}
			}
			if len(caa) > 0 {
				r.AddExtra("caa", caa)
			}
		}
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		if ans, err := queryDNS(resolver, domain, dnsTypeDNSKEY, 5*time.Second); err == nil {
			n := 0
			for _, a := range ans {
				if a.Type == dnsTypeDNSKEY {
					n++
				}
			}
			if n > 0 {
				r.AddExtra("dnskey_count", n)
			}
		}
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		if ans, err := queryDNS(resolver, domain, dnsTypeDS, 5*time.Second); err == nil {
			var ds []map[string]any
			for _, a := range ans {
				if a.Type == dnsTypeDS {
					if d := parseDS(a.RDATA); d != nil {
						ds = append(ds, d)
					}
				}
			}
			if len(ds) > 0 {
				r.AddExtra("ds", ds)
			}
		}
	}()
	wg.Wait()

	if www := "www." + domain; www != domain {
		if ips, err := net.LookupHost(www); err == nil {
			r.AddExtra("www_ips", ips)
		}
	}

	emitFindings(r)
	r.Finish()
	return r, nil
}

func emitFindings(r *core.Result) {
	if _, ok := r.Extra["spf"]; !ok {
		r.Add(core.Finding{Tool: "domainx", Severity: core.SevMed,
			Title: "SPF missing", Detail: "no v=spf1 TXT record at apex"})
	}
	if _, ok := r.Extra["dmarc"]; !ok {
		r.Add(core.Finding{Tool: "domainx", Severity: core.SevMed,
			Title: "DMARC missing", Detail: "no v=DMARC1 TXT at _dmarc"})
	} else if dmarc, ok := r.Extra["dmarc"].(string); ok {
		if strings.Contains(dmarc, "p=none") {
			r.Add(core.Finding{Tool: "domainx", Severity: core.SevMed,
				Title: "DMARC p=none", Detail: "monitoring only, not enforced"})
		}
	}
	if _, ok := r.Extra["dnskey_count"]; !ok {
		r.Add(core.Finding{Tool: "domainx", Severity: core.SevLow,
			Title: "DNSSEC not signed", Detail: "no DNSKEY at apex"})
	} else if _, hasDS := r.Extra["ds"]; !hasDS {
		r.Add(core.Finding{Tool: "domainx", Severity: core.SevLow,
			Title:  "DNSSEC key present but no DS at parent",
			Detail: "chain-of-trust incomplete"})
	}
	if _, ok := r.Extra["caa"]; !ok {
		r.Add(core.Finding{Tool: "domainx", Severity: core.SevLow,
			Title: "CAA missing", Detail: "any CA can issue certs for this domain"})
	}
}

func reverseMX(ctx context.Context, mxs []*net.MX, r *core.Result) {
	var mu sync.Mutex
	out := map[string][]string{}
	var wg sync.WaitGroup
	for _, m := range mxs {
		host := strings.TrimSuffix(m.Host, ".")
		wg.Add(1)
		go func(h string) {
			defer wg.Done()
			ips, err := net.LookupHost(h)
			if err != nil {
				return
			}
			select {
			case <-ctx.Done():
				return
			default:
			}
			mu.Lock()
			out[h] = ips
			mu.Unlock()
		}(host)
	}
	wg.Wait()
	if len(out) > 0 {
		r.AddExtra("mx_ips", out)
	}
}

func pickResolver() string {
	if _, err := net.DialTimeout("udp", "1.1.1.1:53", 2*time.Second); err == nil {
		return "1.1.1.1:53"
	}
	return "8.8.8.8:53"
}

var _ = fmt.Sprintf
