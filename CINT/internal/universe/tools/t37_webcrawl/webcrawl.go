package t37_webcrawl

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	core "github.com/brezzkin-dev/CINT/internal/universe/core"
)

type Options struct {
	Seed     string
	MaxDepth int
	MaxPages int
	SameHost bool
}

type Page struct {
	URL       string   `json:"url"`
	Status    int      `json:"status"`
	Depth     int      `json:"depth"`
	Title     string   `json:"title,omitempty"`
	Links     []string `json:"links,omitempty"`
	Forms     []Form   `json:"forms,omitempty"`
	Scripts   []string `json:"scripts,omitempty"`
	Endpoints []string `json:"endpoints,omitempty"`
	Comments  []string `json:"comments,omitempty"`
}

type Form struct {
	Action string   `json:"action"`
	Method string   `json:"method"`
	Inputs []string `json:"inputs,omitempty"`
}

var (
	reHref      = regexp.MustCompile(`(?is)<a[^>]+href\s*=\s*["']([^"'#][^"']*)["']`)
	reForm      = regexp.MustCompile(`(?is)<form\b([^>]*)>`)
	reAttr      = regexp.MustCompile(`(?is)(\w+)\s*=\s*["']([^"']+)["']`)
	reScript    = regexp.MustCompile(`(?is)<script[^>]+src\s*=\s*["']([^"']+)["']`)
	reTitle     = regexp.MustCompile(`(?is)<title[^>]*>([^<]+)</title>`)
	reEndpoint  = regexp.MustCompile(`["'](/[a-zA-Z0-9_\-]+(?:/[a-zA-Z0-9_\-]+){1,5})["']`)
	reComment   = regexp.MustCompile(`(?s)<!--(.*?)-->`)
	reInputName = regexp.MustCompile(`(?is)<input[^>]+name\s*=\s*["']([^"']+)["']`)
)

func Run(opts Options) (*core.Result, error) {
	r := core.NewResult("webcrawl", opts.Seed)

	seedURL, err := url.Parse(opts.Seed)
	if err != nil {
		return r, err
	}
	if seedURL.Scheme != "http" && seedURL.Scheme != "https" {
		return r, fmt.Errorf("scheme %q not allowed", seedURL.Scheme)
	}
	if err := assertSafeHost(seedURL.Hostname()); err != nil {
		return r, err
	}

	if opts.MaxDepth <= 0 {
		opts.MaxDepth = 3
	}
	if opts.MaxPages <= 0 {
		opts.MaxPages = 100
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	robotsURL := seedURL.Scheme + "://" + seedURL.Host + "/robots.txt"
	if status, _, body, _ := core.HTTPGet(ctx, robotsURL, nil); status == 200 {
		r.AddExtra("robots_txt", string(body))
	}

	type queueItem struct {
		url   string
		depth int
	}

	queue := []queueItem{{seedURL.String(), 0}}
	visited := map[string]bool{seedURL.String(): true}
	var pages []Page
	baseline := seedURL.Hostname()

	for len(queue) > 0 && len(pages) < opts.MaxPages {
		batchSize := 4
		if len(queue) < batchSize {
			batchSize = len(queue)
		}
		if len(pages)+batchSize > opts.MaxPages {
			batchSize = opts.MaxPages - len(pages)
		}
		batch := append([]queueItem{}, queue[:batchSize]...)
		queue = queue[batchSize:]

		type res struct {
			page  Page
			urls  []string
			depth int
		}
		results := make([]res, batchSize)
		var wg sync.WaitGroup
		for i, item := range batch {
			wg.Add(1)
			go func(i int, item queueItem) {
				defer wg.Done()
				p, urls := fetchAndParse(ctx, item.url, item.depth, baseline, opts.SameHost)
				results[i] = res{p, urls, item.depth}
			}(i, item)
		}
		wg.Wait()

		for _, x := range results {
			pages = append(pages, x.page)
			for _, u := range x.urls {
				if visited[u] || len(visited) >= opts.MaxPages*3 {
					continue
				}
				visited[u] = true
				if x.depth+1 <= opts.MaxDepth {
					queue = append(queue, queueItem{u, x.depth + 1})
				}
			}
		}
	}

	r.AddExtra("pages", pages)
	r.AddExtra("page_count", len(pages))

	for _, p := range pages {
		for _, f := range p.Forms {
			r.Add(core.Finding{Tool: "webcrawl", Severity: core.SevInfo,
				Title:    "form: " + f.Action,
				Evidence: map[string]any{"method": f.Method, "inputs": f.Inputs, "page": p.URL}})
		}
	}
	if len(pages) > 0 {
		r.Add(core.Finding{Tool: "webcrawl", Severity: core.SevInfo,
			Title: fmt.Sprintf("%d pages crawled", len(pages))})
	}

	r.Finish()
	return r, nil
}

func fetchAndParse(ctx context.Context, rawURL string, depth int, baseline string, sameHost bool) (Page, []string) {
	p := Page{URL: rawURL, Depth: depth}

	u, err := url.Parse(rawURL)
	if err != nil {
		return p, nil
	}
	if err := assertSafeHost(u.Hostname()); err != nil {
		p.Status = -1
		return p, nil
	}

	status, _, body, err := core.HTTPGet(ctx, rawURL, map[string]string{
		"User-Agent": "CINT-Webcrawl/1.0",
		"Accept":     "text/html,*/*;q=0.8",
	})
	if err != nil {
		p.Status = -1
		return p, nil
	}
	p.Status = status

	s := string(body)
	if t := reTitle.FindStringSubmatch(s); len(t) > 1 {
		p.Title = strings.TrimSpace(t[1])
	}

	var newURLs []string
	for _, m := range reHref.FindAllStringSubmatch(s, 500) {
		link := strings.TrimSpace(m[1])
		link = strings.SplitN(link, "#", 2)[0]
		link = strings.SplitN(link, "?", 2)[0]
		if link == "" || strings.HasPrefix(strings.ToLower(link), "javascript:") ||
			strings.HasPrefix(strings.ToLower(link), "mailto:") {
			continue
		}
		abs := resolveURL(u, link)
		if abs == "" {
			continue
		}
		au, _ := url.Parse(abs)
		if au == nil {
			continue
		}
		if sameHost && au.Hostname() != baseline {
			continue
		}
		p.Links = append(p.Links, abs)
		newURLs = append(newURLs, abs)
		if len(p.Links) >= 200 {
			break
		}
	}

	for _, m := range reForm.FindAllStringSubmatch(s, 50) {
		attrs := m[1]
		form := Form{Action: rawURL, Method: "GET"}
		for _, a := range reAttr.FindAllStringSubmatch(attrs, -1) {
			k, v := strings.ToLower(a[1]), a[2]
			switch k {
			case "action":
				form.Action = resolveURL(u, v)
			case "method":
				form.Method = strings.ToUpper(v)
			}
		}
		p.Forms = append(p.Forms, form)
	}
	for i := range p.Forms {
		for _, m := range reInputName.FindAllStringSubmatch(s, 20) {
			p.Forms[i].Inputs = append(p.Forms[i].Inputs, m[1])
			if len(p.Forms[i].Inputs) >= 10 {
				break
			}
		}
	}

	for _, m := range reScript.FindAllStringSubmatch(s, 100) {
		p.Scripts = append(p.Scripts, resolveURL(u, strings.TrimSpace(m[1])))
	}

	seen := map[string]bool{}
	for _, m := range reEndpoint.FindAllStringSubmatch(s, 200) {
		e := m[1]
		if !seen[e] {
			seen[e] = true
			p.Endpoints = append(p.Endpoints, e)
			if len(p.Endpoints) >= 50 {
				break
			}
		}
	}

	for _, m := range reComment.FindAllStringSubmatch(s, 20) {
		c := strings.TrimSpace(m[1])
		if len(c) > 4 {
			p.Comments = append(p.Comments, c)
		}
	}

	return p, newURLs
}

func resolveURL(base *url.URL, ref string) string {
	r, err := url.Parse(ref)
	if err != nil {
		return ""
	}
	return base.ResolveReference(r).String()
}

func assertSafeHost(host string) error {
	if host == "" {
		return fmt.Errorf("empty host")
	}
	if ip := net.ParseIP(host); ip != nil {
		if isBlocked(ip) {
			return fmt.Errorf("destination %s is blocked", ip)
		}
		return nil
	}
	addrs, err := net.LookupHost(host)
	if err != nil {
		return err
	}
	for _, a := range addrs {
		if ip := net.ParseIP(a); ip != nil && isBlocked(ip) {
			return fmt.Errorf("host resolves to blocked %s", a)
		}
	}
	return nil
}

func isBlocked(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified()
}
