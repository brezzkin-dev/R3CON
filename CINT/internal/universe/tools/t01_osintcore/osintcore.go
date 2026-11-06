package t01_osintcore

import (
	"fmt"
	"net"
	"strings"

	core "github.com/brezzkin-dev/CINT/internal/universe/core"
	"github.com/brezzkin-dev/CINT/internal/universe/tools/t03_domaintrace"
	"github.com/brezzkin-dev/CINT/internal/universe/tools/t04_ipintel"
	"github.com/brezzkin-dev/CINT/internal/universe/tools/t05_userfinder"
	"github.com/brezzkin-dev/CINT/internal/universe/tools/t06_mailtrace"
)

// Run routes a target to the appropriate sub-tool by IOC type and merges
// findings into a single report.
func Run(target string) (*core.Result, error) {
	r := core.NewResult("osintcore", target)
	target = strings.TrimSpace(target)

	kind := core.Classify(target)
	r.AddExtra("target_kind", string(kind))

	switch kind {
	case core.IOCIPv4, core.IOCIPv6:
		sub, err := t04_ipintel.Run(target)
		if err == nil {
			merge(r, sub, "ipintel")
		}
	case core.IOCDomain, core.IOCURL:
		host := target
		if kind == core.IOCURL {
			if u := parseHost(target); u != "" {
				host = u
			}
		}
		sub, err := t03_domaintrace.Run(host)
		if err == nil {
			merge(r, sub, "domaintrace")
		}
		if net.ParseIP(host) == nil {
			if ips, err := net.LookupHost(host); err == nil && len(ips) > 0 {
				ipr, err := t04_ipintel.Run(ips[0])
				if err == nil {
					merge(r, ipr, "ipintel")
				}
			}
		}
	case core.IOCEmail:
		sub, err := t06_mailtrace.Run(target)
		if err == nil {
			merge(r, sub, "mailtrace")
		}
	default:
		sub, err := t05_userfinder.Run(target)
		if err == nil {
			merge(r, sub, "userfinder")
		}
	}

	r.Add(core.Finding{
		Tool: "osintcore", Severity: core.SevInfo,
		Title:  "OSINT complete",
		Detail: fmt.Sprintf("%d sub-findings", len(r.Findings)),
	})
	r.Finish()
	return r, nil
}

func merge(dst, src *core.Result, source string) {
	for _, f := range src.Findings {
		f.Tool = dst.Tool + "/" + source
		dst.Findings = append(dst.Findings, f)
	}
	if src.Extra != nil {
		dst.AddExtra(source, src.Extra)
	}
}

func parseHost(raw string) string {
	s := raw
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/:?#"); i >= 0 {
		s = s[:i]
	}
	return s
}
