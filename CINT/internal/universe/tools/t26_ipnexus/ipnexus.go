package t26_ipnexus

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

const (
	geoAPI  = "http://ip-api.com/json/%s?fields=status,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query"
	rdapURL = "https://rdap.org/ip/%s"
	torURL  = "https://check.torproject.org/torbulkexitlist"
)

var torCache struct {
	loaded bool
	set    map[string]bool
}

func loadTorExit(ctx context.Context) map[string]bool {
	if torCache.loaded {
		return torCache.set
	}
	torCache.set = map[string]bool{}
	status, _, body, err := core.HTTPGet(ctx, torURL, nil)
	if err != nil || status != 200 {
		return torCache.set
	}
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			torCache.set[line] = true
		}
	}
	torCache.loaded = true
	return torCache.set
}

func Run(ipStr string) (*core.Result, error) {
	r := core.NewResult("ipnexus", ipStr)
	ctx := context.Background()

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return r, fmt.Errorf("invalid IP: %s", ipStr)
	}

	if ip4 := ip.To4(); ip4 != nil {
		r.AddExtra("version", 4)
		r.AddExtra("cidr", ip4.String())
	} else {
		r.AddExtra("version", 6)
		if strings.HasPrefix(strings.ToLower(ipStr), "::ffff:") {
			r.AddExtra("ipv4_mapped", true)
			if v4 := ip.To4(); v4 != nil {
				r.AddExtra("underlying_v4", v4.String())
			}
		}
	}

	if g := lookupGeo(ctx, ipStr); g != nil {
		r.AddExtra("geo", g)
		if country, ok := g["country"].(string); ok {
			r.Add(core.Finding{
				Tool: "ipnexus", Severity: core.SevInfo,
				Title: "Geolocation",
				Detail: fmt.Sprintf("%s, %s — %s",
					toStr(g["city"]), country, toStr(g["isp"])),
			})
		}
		if as, ok := g["as"].(string); ok {
			r.AddExtra("asn", as)
		}
		if proxy, ok := g["proxy"].(bool); ok && proxy {
			r.Add(core.Finding{Tool: "ipnexus", Severity: core.SevHigh,
				Title: "Proxy/VPN detected"})
		}
		if hosting, ok := g["hosting"].(bool); ok && hosting {
			r.Add(core.Finding{Tool: "ipnexus", Severity: core.SevLow,
				Title: "Datacenter / hosting IP"})
		}
		if mobile, ok := g["mobile"].(bool); ok && mobile {
			r.AddExtra("mobile", true)
		}
	}

	if rd := lookupRDAP(ctx, ipStr); rd != nil {
		r.AddExtra("rdap", rd)
		if name, ok := rd["name"].(string); ok {
			r.AddExtra("network_name", name)
		}
		if start, ok := rd["startAddress"].(string); ok {
			if end, ok := rd["endAddress"].(string); ok {
				r.AddExtra("network_range", start+" - "+end)
				if size := cidrSize(start, end); size > 0 {
					r.AddExtra("network_size_ips", size)
				}
			}
		}
		if entities, ok := rd["entities"].([]any); ok {
			r.AddExtra("rdap_entities", entities)
		}
	}

	if names, err := net.LookupAddr(ipStr); err == nil && len(names) > 0 {
		r.AddExtra("reverse_dns", names)
	}

	torSet := loadTorExit(ctx)
	if torSet[ipStr] {
		r.Add(core.Finding{
			Tool: "ipnexus", Severity: core.SevHigh,
			Title:  "Tor exit node",
			Detail: "IP is a known Tor exit relay",
		})
		r.AddExtra("tor_exit", true)
	} else {
		r.AddExtra("tor_exit", false)
	}

	if cert := grabTLSCert(ipStr); cert != nil {
		r.AddExtra("tls_cert", cert)
		r.AddExtra("tls_cert_verified", false)
	}

	r.Finish()
	return r, nil
}

func lookupGeo(ctx context.Context, ip string) map[string]any {
	status, _, body, err := core.HTTPGet(ctx, fmt.Sprintf(geoAPI, ip), nil)
	if err != nil || status != 200 {
		return nil
	}
	var out map[string]any
	if json.Unmarshal(body, &out) != nil {
		return nil
	}
	if s, ok := out["status"].(string); ok && s == "success" {
		return out
	}
	return nil
}

func lookupRDAP(ctx context.Context, ip string) map[string]any {
	status, _, body, err := core.HTTPGet(ctx, fmt.Sprintf(rdapURL, ip),
		map[string]string{"Accept": "application/rdap+json"})
	if err != nil || status != 200 {
		return nil
	}
	var out map[string]any
	if json.Unmarshal(body, &out) != nil {
		return nil
	}
	return out
}

func cidrSize(start, end string) uint64 {
	s := net.ParseIP(start).To4()
	e := net.ParseIP(end).To4()
	if s == nil || e == nil {
		return 0
	}
	sNum := uint64(s[0])<<24 | uint64(s[1])<<16 | uint64(s[2])<<8 | uint64(s[3])
	eNum := uint64(e[0])<<24 | uint64(e[1])<<16 | uint64(e[2])<<8 | uint64(e[3])
	if eNum < sNum {
		return 0
	}
	return eNum - sNum + 1
}

func grabTLSCert(ip string) map[string]any {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", ip+":443",
		&tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return nil
	}
	defer conn.Close()
	st := conn.ConnectionState()
	if len(st.PeerCertificates) == 0 {
		return nil
	}
	c := st.PeerCertificates[0]
	return map[string]any{
		"subject":    c.Subject.String(),
		"issuer":     c.Issuer.String(),
		"not_before": c.NotBefore.Format(time.RFC3339),
		"not_after":  c.NotAfter.Format(time.RFC3339),
		"dns_names":  c.DNSNames,
		"serial":     c.SerialNumber.String(),
	}
}

func toStr(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}
