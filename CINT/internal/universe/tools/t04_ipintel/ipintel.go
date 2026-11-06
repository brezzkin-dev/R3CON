package t04_ipintel

import (
	"context"
	"encoding/json"
	"fmt"
	"net"

	core "github.com/brezzkin-dev/CINT/internal/universe/core"
)

func Run(ip string) (*core.Result, error) {
	r := core.NewResult("ipintel", ip)
	ctx := context.Background()

	if net.ParseIP(ip) == nil {
		return r, fmt.Errorf("invalid IP: %s", ip)
	}

	url := fmt.Sprintf("http://ip-api.com/json/%s?fields=status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query", ip)
	status, _, body, err := core.HTTPGet(ctx, url, nil)
	if err == nil && status == 200 {
		var out map[string]any
		if json.Unmarshal(body, &out) == nil {
			r.AddExtra("ip_api", out)
			if s, ok := out["status"].(string); ok && s == "success" {
				r.Add(core.Finding{
					Tool: "ipintel", Severity: core.SevInfo,
					Title: "Located",
					Detail: fmt.Sprintf("%s, %s — %s",
						asStr(out["city"]), asStr(out["country"]), asStr(out["isp"])),
					Evidence: out,
				})
				if b, ok := out["proxy"].(bool); ok && b {
					r.Add(core.Finding{Tool: "ipintel", Severity: core.SevHigh,
						Title: "Proxy / VPN detected"})
				}
				if b, ok := out["hosting"].(bool); ok && b {
					r.Add(core.Finding{Tool: "ipintel", Severity: core.SevLow,
						Title: "Datacenter / hosting IP"})
				}
			}
		}
	}

	rdapURL := fmt.Sprintf("https://rdap.org/ip/%s", ip)
	if status, _, b, err := core.HTTPGet(ctx, rdapURL, map[string]string{"Accept": "application/rdap+json"}); err == nil && status == 200 {
		var out map[string]any
		if json.Unmarshal(b, &out) == nil {
			r.AddExtra("rdap", out)
		}
	}

	if names, err := net.LookupAddr(ip); err == nil && len(names) > 0 {
		r.AddExtra("reverse_dns", names)
	}

	r.Finish()
	return r, nil
}

func asStr(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}
