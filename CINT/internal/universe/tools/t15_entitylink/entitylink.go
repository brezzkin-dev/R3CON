package t15_entitylink

import (
	"net"
	"strings"

	core "github.com/brezzkin-dev/CINT/internal/universe/core"
	"github.com/brezzkin-dev/CINT/internal/universe/tools/t03_domaintrace"
	"github.com/brezzkin-dev/CINT/internal/universe/tools/t04_ipintel"
	"github.com/brezzkin-dev/CINT/internal/universe/tools/t05_userfinder"
	"github.com/brezzkin-dev/CINT/internal/universe/tools/t06_mailtrace"
)

// Run cross-correlates an entity: email → domain → IPs → ASN, plus
// local-part → username → platform presence. Output is a linked graph.
func Run(target string) (*core.Result, error) {
	r := core.NewResult("entitylink", target)
	target = strings.TrimSpace(target)

	entities := map[string]string{}
	var domains []string
	var ips []string
	var users []string
	var emails []string

	kind := core.Classify(target)
	switch kind {
	case core.IOCEmail:
		emails = append(emails, target)
		entities[target] = "email"
		if at := strings.LastIndex(target, "@"); at >= 0 {
			d := target[at+1:]
			domains = append(domains, d)
			entities[d] = "domain"
			users = append(users, target[:at])
			entities[target[:at]] = "username"
		}
	case core.IOCDomain, core.IOCURL:
		host := target
		if kind == core.IOCURL {
			if i := strings.Index(host, "://"); i >= 0 {
				host = host[i+3:]
			}
			if i := strings.IndexAny(host, "/:?#"); i >= 0 {
				host = host[:i]
			}
		}
		domains = append(domains, host)
		entities[host] = "domain"
		if resolved, _ := net.LookupHost(host); len(resolved) > 0 {
			for _, ip := range resolved {
				entities[ip] = "ip"
				ips = append(ips, ip)
			}
		}
	case core.IOCIPv4, core.IOCIPv6:
		ips = append(ips, target)
		entities[target] = "ip"
	default:
		users = append(users, target)
		entities[target] = "username"
	}

	for _, d := range domains {
		dt, err := t03_domaintrace.Run(d)
		if err == nil {
			r.AddExtra("domaintrace:"+d, dt.Extra)
			for _, f := range dt.Findings {
				f.Tool = "entitylink"
				r.Findings = append(r.Findings, f)
			}
		}
	}

	seenIP := map[string]bool{}
	for _, ip := range ips {
		if seenIP[ip] {
			continue
		}
		seenIP[ip] = true
		ipr, err := t04_ipintel.Run(ip)
		if err == nil {
			r.AddExtra("ipintel:"+ip, ipr.Extra)
			for _, f := range ipr.Findings {
				f.Tool = "entitylink"
				r.Findings = append(r.Findings, f)
			}
		}
	}

	for _, em := range emails {
		mr, err := t06_mailtrace.Run(em)
		if err == nil {
			r.AddExtra("mailtrace:"+em, mr.Extra)
		}
	}

	for _, u := range users {
		uf, err := t05_userfinder.Run(u)
		if err == nil {
			r.AddExtra("userfinder:"+u, uf.Extra)
			for _, f := range uf.Findings {
				f.Tool = "entitylink"
				r.Findings = append(r.Findings, f)
			}
		}
	}

	entitiesOut := make([]map[string]string, 0, len(entities))
	for v, t := range entities {
		entitiesOut = append(entitiesOut, map[string]string{"value": v, "type": t})
	}
	r.AddExtra("entities", entitiesOut)
	r.AddExtra("entity_count", len(entities))

	r.Add(core.Finding{
		Tool: "entitylink", Severity: core.SevInfo,
		Title:  "Entity graph built",
		Detail: itoa(len(entities)) + " linked entities",
	})
	r.Finish()
	return r, nil
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
