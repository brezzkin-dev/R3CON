package t03_domaintrace

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	core "github.com/brezzkin-dev/CINT/internal/universe/core"
)

func Run(domain string) (*core.Result, error) {
	r := core.NewResult("domaintrace", domain)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	if ips, err := net.LookupHost(domain); err == nil {
		r.AddExtra("a_records", ips)
	}
	if mxs, err := net.LookupMX(domain); err == nil {
		out := make([]map[string]any, len(mxs))
		for i, m := range mxs {
			out[i] = map[string]any{"host": m.Host, "pref": m.Pref}
		}
		r.AddExtra("mx", out)
	}
	if nss, err := net.LookupNS(domain); err == nil {
		out := make([]string, len(nss))
		for i, n := range nss {
			out[i] = n.Host
		}
		r.AddExtra("ns", out)
	}
	if txts, err := net.LookupTXT(domain); err == nil {
		r.AddExtra("txt", txts)
		for _, t := range txts {
			if strings.HasPrefix(t, "v=spf1") {
				r.Add(core.Finding{Tool: "domaintrace", Severity: core.SevInfo,
					Title: "SPF present", Detail: t})
			}
		}
	}
	if dmarcs, err := net.LookupTXT("_dmarc." + domain); err == nil {
		for _, t := range dmarcs {
			if strings.HasPrefix(t, "v=DMARC1") {
				r.Add(core.Finding{Tool: "domaintrace", Severity: core.SevInfo,
					Title: "DMARC present", Detail: t})
			}
		}
	}

	if err := queryRDAP(ctx, domain, r); err != nil {
		core.Debugf("rdap: %v", err)
	}
	if err := queryCT(ctx, domain, r); err != nil {
		core.Debugf("crt.sh: %v", err)
	}

	r.Finish()
	return r, nil
}

func queryRDAP(ctx context.Context, domain string, r *core.Result) error {
	url := "https://rdap.org/domain/" + domain
	status, _, body, err := core.HTTPGet(ctx, url, map[string]string{"Accept": "application/rdap+json"})
	if err != nil || status != 200 {
		return fmt.Errorf("rdap http %d", status)
	}
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		return err
	}
	r.AddExtra("rdap", out)
	if entities, ok := out["entities"].([]any); ok {
		for _, e := range entities {
			if em, ok := e.(map[string]any); ok {
				if roles, ok := em["roles"].([]any); ok {
					for _, role := range roles {
						if rs, ok := role.(string); ok && rs == "registrar" {
							if vc, ok := em["vcardArray"].([]any); ok {
								r.AddExtra("registrar_vcard", vc)
							}
						}
					}
				}
			}
		}
	}
	if events, ok := out["events"].([]any); ok {
		for _, e := range events {
			if em, ok := e.(map[string]any); ok {
				if action, ok := em["eventAction"].(string); ok {
					r.Add(core.Finding{
						Tool: "domaintrace", Severity: core.SevInfo,
						Title:  "domain " + action,
						Detail: toStr(em["eventDate"]),
					})
				}
			}
		}
	}
	return nil
}

func queryCT(ctx context.Context, domain string, r *core.Result) error {
	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)
	status, _, body, err := core.HTTPGet(ctx, url, nil)
	if err != nil || status != 200 {
		return fmt.Errorf("crt http %d", status)
	}
	var raw []struct {
		NameValue string `json:"name_value"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return err
	}
	seen := map[string]bool{}
	var names []string
	for _, c := range raw {
		for _, line := range strings.Split(c.NameValue, "\n") {
			line = strings.TrimSpace(strings.TrimPrefix(line, "*."))
			if line != "" && strings.HasSuffix(line, domain) && !seen[line] {
				seen[line] = true
				names = append(names, line)
			}
		}
	}
	if len(names) > 300 {
		names = names[:300]
	}
	r.AddExtra("ct_names", names)
	r.AddExtra("ct_count", len(names))
	if len(names) > 0 {
		r.Add(core.Finding{
			Tool: "domaintrace", Severity: core.SevInfo,
			Title:  fmt.Sprintf("%d subdomains from CT logs", len(names)),
			Detail: strings.Join(names[:minInt(5, len(names))], ", "),
		})
	}
	return nil
}

func toStr(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
