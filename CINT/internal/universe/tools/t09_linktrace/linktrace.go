package t09_linktrace

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	core "github.com/brezzkin-dev/CINT/internal/universe/core"
	"github.com/brezzkin-dev/CINT/internal/universe/tools/t03_domaintrace"
)

const maxHops = 10

func Run(rawURL string) (*core.Result, error) {
	r := core.NewResult("linktrace", rawURL)
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		return r, fmt.Errorf("linktrace: only http/https accepted")
	}
	initial, err := url.Parse(rawURL)
	if err != nil {
		return r, err
	}
	if initial.User != nil {
		return r, fmt.Errorf("linktrace: URL must not contain credentials")
	}
	if err := assertSafeURL(initial); err != nil {
		return r, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	chain := []string{rawURL}
	cur := rawURL
	var lastStatus int

	for i := 0; i < maxHops; i++ {
		u, perr := url.Parse(cur)
		if perr != nil {
			r.Add(core.Finding{Tool: "linktrace", Severity: core.SevLow,
				Title: "bad hop URL", Detail: perr.Error()})
			break
		}
		if err := assertSafeURL(u); err != nil {
			r.Add(core.Finding{Tool: "linktrace", Severity: core.SevMed,
				Title: "blocked hop (SSRF guard)", Detail: cur + " — " + err.Error()})
			break
		}
		status, headers, _, ferr := core.HTTPGet(ctx, cur,
			map[string]string{"User-Agent": "Mozilla/5.0 (linktrace)"})
		if ferr != nil {
			r.Add(core.Finding{Tool: "linktrace", Severity: core.SevLow,
				Title: fmt.Sprintf("fetch error at hop %d", i), Detail: ferr.Error()})
			break
		}
		lastStatus = status
		loc := headers.Get("Location")
		if loc == "" || status < 300 || status >= 400 {
			break
		}
		next, perr := url.Parse(loc)
		if perr != nil {
			break
		}
		base, _ := url.Parse(cur)
		cur = base.ResolveReference(next).String()
		chain = append(chain, cur)
	}

	r.AddExtra("final_status", lastStatus)
	r.AddExtra("redirect_chain", chain)
	r.AddExtra("hop_count", len(chain)-1)

	if len(chain) > 1 {
		lastU, err := url.Parse(chain[len(chain)-1])
		if err == nil {
			host := lastU.Hostname()
			if host != initial.Hostname() {
				r.Add(core.Finding{
					Tool: "linktrace", Severity: core.SevMed,
					Title:  "Cross-domain redirect",
					Detail: initial.Hostname() + " → " + host,
				})
				dt, err := t03_domaintrace.Run(host)
				if err == nil {
					r.AddExtra("domaintrace", dt.Extra)
				}
			}
		}
	}

	r.AddExtra("initial_host", initial.Hostname())
	r.AddExtra("initial_scheme", initial.Scheme)
	r.Finish()
	return r, nil
}

func assertSafeURL(u *url.URL) error {
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("scheme %q not allowed", u.Scheme)
	}
	if u.User != nil {
		return fmt.Errorf("credentials in URL not allowed")
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("empty host")
	}
	if ip := net.ParseIP(host); ip != nil {
		if isBlockedIP(ip) {
			return fmt.Errorf("destination %s is not a public address", ip)
		}
		return nil
	}
	addrs, err := net.LookupHost(host)
	if err != nil {
		return fmt.Errorf("resolve %s: %w", host, err)
	}
	for _, a := range addrs {
		ip := net.ParseIP(a)
		if ip == nil {
			continue
		}
		if isBlockedIP(ip) {
			return fmt.Errorf("host %s resolves to blocked address %s", host, a)
		}
	}
	return nil
}

func isBlockedIP(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified()
}
