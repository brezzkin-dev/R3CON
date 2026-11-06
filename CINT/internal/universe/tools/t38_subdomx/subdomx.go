package t38_subdomx

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	core "github.com/brezzkin-dev/CINT/internal/universe/core"
)

var (
	reSubdomain = regexp.MustCompile(`\b([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b`)
	reRapidRow  = regexp.MustCompile(`(?is)<td>([^<]*?\.` + `[a-z]{2,}[^<]*)</td>`)
)

type source struct {
	Name string
	Fn   func(context.Context, string) ([]string, error)
}

func Run(domain string, resolve bool) (*core.Result, error) {
	r := core.NewResult("subdomx", domain)
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return r, fmt.Errorf("empty domain")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	sources := []source{
		{"crtsh", crtSh},
		{"hackertarget", hackerTarget},
		{"rapiddns", rapidDNS},
		{"anubis", anubis},
		{"alienvault", alienvaultOTX},
	}

	var mu sync.Mutex
	allNames := map[string]bool{}
	sourceCounts := map[string]int{}
	var wg sync.WaitGroup

	for _, s := range sources {
		wg.Add(1)
		go func(s source) {
			defer wg.Done()
			names, err := s.Fn(ctx, domain)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				sourceCounts[s.Name+"_error"]++
				return
			}
			sourceCounts[s.Name] = len(names)
			for _, n := range names {
				n = strings.ToLower(strings.TrimSpace(n))
				n = strings.TrimPrefix(n, "*.")
				if n != "" && strings.HasSuffix(n, domain) {
					allNames[n] = true
				}
			}
		}(s)
	}
	wg.Wait()

	names := make([]string, 0, len(allNames))
	for n := range allNames {
		names = append(names, n)
	}
	sort.Strings(names)

	r.AddExtra("count", len(names))
	r.AddExtra("source_counts", sourceCounts)
	r.AddExtra("subdomains", names)

	if resolve && len(names) > 0 {
		resolved := resolveAll(ctx, names)
		r.AddExtra("resolved", resolved)
	}

	if len(names) > 0 {
		r.Add(core.Finding{Tool: "subdomx", Severity: core.SevInfo,
			Title:  fmt.Sprintf("%d unique subdomains", len(names)),
			Detail: strings.Join(firstN(names, 5), ", ")})
	}
	r.Finish()
	return r, nil
}

func crtSh(ctx context.Context, domain string) ([]string, error) {
	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)
	status, _, body, err := core.HTTPGet(ctx, url, nil)
	if err != nil || status != 200 {
		return nil, fmt.Errorf("crt.sh http %d", status)
	}
	var raw []struct {
		NameValue string `json:"name_value"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, err
	}
	var out []string
	for _, r := range raw {
		for _, line := range strings.Split(r.NameValue, "\n") {
			line = strings.TrimSpace(line)
			if line != "" {
				out = append(out, line)
			}
		}
	}
	return out, nil
}

func hackerTarget(ctx context.Context, domain string) ([]string, error) {
	url := "https://api.hackertarget.com/hostsearch/?q=" + domain
	status, _, body, err := core.HTTPGet(ctx, url, nil)
	if err != nil || status != 200 {
		return nil, fmt.Errorf("hackertarget http %d", status)
	}
	s := string(body)
	if strings.HasPrefix(s, "error") || strings.HasPrefix(s, "API count") {
		return nil, fmt.Errorf("hackertarget rate-limited")
	}
	var out []string
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if i := strings.Index(line, ","); i > 0 {
			out = append(out, line[:i])
		}
	}
	return out, nil
}

func rapidDNS(ctx context.Context, domain string) ([]string, error) {
	url := "https://rapiddns.io/subdomain/" + domain + "?full=1"
	status, _, body, err := core.HTTPGet(ctx, url, nil)
	if err != nil || status != 200 {
		return nil, fmt.Errorf("rapiddns http %d", status)
	}
	var out []string
	for _, m := range reRapidRow.FindAllStringSubmatch(string(body), -1) {
		if len(m) > 1 {
			candidate := strings.TrimSpace(m[1])
			if strings.HasSuffix(candidate, domain) {
				out = append(out, candidate)
			}
		}
	}
	for _, m := range reSubdomain.FindAllString(string(body), 1000) {
		if strings.HasSuffix(m, domain) && m != domain {
			out = append(out, m)
		}
	}
	return out, nil
}

func anubis(ctx context.Context, domain string) ([]string, error) {
	url := "https://jldc.me/anubis/subdomains/" + domain
	status, _, body, err := core.HTTPGet(ctx, url, nil)
	if err != nil || status != 200 {
		return nil, fmt.Errorf("anubis http %d", status)
	}
	var arr []string
	if err := json.Unmarshal(body, &arr); err != nil {
		return nil, err
	}
	return arr, nil
}

func alienvaultOTX(ctx context.Context, domain string) ([]string, error) {
	url := "https://otx.alienvault.com/api/v1/indicators/domain/" + domain + "/passive_dns"
	status, _, body, err := core.HTTPGet(ctx, url, nil)
	if err != nil || status != 200 {
		return nil, fmt.Errorf("otx http %d", status)
	}
	var out struct {
		PassiveDNS []struct {
			Hostname string `json:"hostname"`
		} `json:"passive_dns"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	var names []string
	for _, e := range out.PassiveDNS {
		if e.Hostname != "" {
			names = append(names, e.Hostname)
		}
	}
	return names, nil
}

func resolveAll(ctx context.Context, names []string) map[string][]string {
	resolved := map[string][]string{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 32)

	for _, n := range names {
		wg.Add(1)
		go func(n string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			select {
			case <-ctx.Done():
				return
			default:
			}
			ips, err := net.LookupHost(n)
			if err != nil || len(ips) == 0 {
				return
			}
			mu.Lock()
			resolved[n] = ips
			mu.Unlock()
		}(n)
	}
	wg.Wait()
	return resolved
}

func firstN(s []string, n int) []string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
