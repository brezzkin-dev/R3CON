package t22_shadowtrace

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"

	core "github.com/brezzkin-dev/CINT/internal/universe/core"
)

type Trace struct {
	Source string         `json:"source"`
	Kind   string         `json:"kind"`
	Hits   []string       `json:"hits,omitempty"`
	Data   map[string]any `json:"data,omitempty"`
}

// Run correlates public traces of an identity across independent sources:
// DNS, CT logs, GitHub code search, crt.sh, gravatar, HackerTarget
// reverse-IP, and WayBack availability. Every lookup is a real public
// feed — no auth required.
func Run(target string) (*core.Result, error) {
	r := core.NewResult("shadowtrace", target)
	ctx := context.Background()
	target = strings.TrimSpace(target)
	if target == "" {
		return r, fmt.Errorf("empty target")
	}

	var traces []Trace
	var mu sync.Mutex
	var wg sync.WaitGroup

	kind := core.Classify(target)
	r.AddExtra("kind", string(kind))

	lookups := []func() *Trace{
		func() *Trace { return traceDNS(ctx, target) },
		func() *Trace { return traceCT(ctx, target) },
		func() *Trace { return traceGitHub(ctx, target) },
		func() *Trace { return traceWayback(ctx, target) },
		func() *Trace { return traceGravatar(ctx, target) },
		func() *Trace { return traceHackerTarget(ctx, target) },
	}

	for _, fn := range lookups {
		wg.Add(1)
		go func(f func() *Trace) {
			defer wg.Done()
			if t := f(); t != nil && (len(t.Hits) > 0 || len(t.Data) > 0) {
				mu.Lock()
				traces = append(traces, *t)
				mu.Unlock()
			}
		}(fn)
	}
	wg.Wait()

	allHits := map[string]int{}
	for _, t := range traces {
		seen := map[string]bool{}
		var uniq []string
		for _, h := range t.Hits {
			if !seen[h] && h != "" {
				seen[h] = true
				uniq = append(uniq, h)
				allHits[h]++
			}
		}
		if len(uniq) > 0 {
			r.Add(core.Finding{
				Tool: "shadowtrace", Severity: core.SevInfo,
				Title:    t.Source,
				Detail:   fmt.Sprintf("%d hits", len(uniq)),
				Evidence: map[string]any{"hits": uniq[:minInt(10, len(uniq))]},
			})
		}
	}

	r.AddExtra("traces", traces)
	r.AddExtra("unique_hits", len(allHits))

	for h, count := range allHits {
		if count >= 2 {
			r.Add(core.Finding{
				Tool: "shadowtrace", Severity: core.SevMed,
				Title:  "corroborated across sources",
				Detail: fmt.Sprintf("%s (%d sources)", h, count),
			})
		}
	}

	r.Finish()
	return r, nil
}

func traceDNS(ctx context.Context, host string) *Trace {
	t := &Trace{Source: "dns"}
	if net.ParseIP(host) != nil {
		if names, err := net.LookupAddr(host); err == nil {
			t.Hits = append(t.Hits, names...)
		}
		t.Kind = "reverse_dns"
		return t
	}
	if ips, err := net.LookupHost(host); err == nil {
		t.Hits = append(t.Hits, ips...)
	}
	if mxs, err := net.LookupMX(host); err == nil {
		for _, m := range mxs {
			t.Hits = append(t.Hits, m.Host)
		}
	}
	if nss, err := net.LookupNS(host); err == nil {
		for _, n := range nss {
			t.Hits = append(t.Hits, n.Host)
		}
	}
	t.Kind = "dns"
	return t
}

func traceCT(ctx context.Context, host string) *Trace {
	t := &Trace{Source: "crt.sh", Kind: "ct_log"}
	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", host)
	status, _, body, err := core.HTTPGet(ctx, url, nil)
	if err != nil || status != 200 {
		return nil
	}
	var raw []struct {
		NameValue string `json:"name_value"`
	}
	if json.Unmarshal(body, &raw) != nil {
		return nil
	}
	seen := map[string]bool{}
	for _, r := range raw {
		for _, line := range strings.Split(r.NameValue, "\n") {
			line = strings.TrimSpace(strings.TrimPrefix(line, "*."))
			if line != "" && strings.HasSuffix(line, host) && !seen[line] {
				seen[line] = true
				t.Hits = append(t.Hits, line)
				if len(t.Hits) >= 100 {
					return t
				}
			}
		}
	}
	return t
}

func traceGitHub(ctx context.Context, q string) *Trace {
	t := &Trace{Source: "github", Kind: "code_search"}
	url := fmt.Sprintf("https://api.github.com/search/code?q=%s&per_page=20", urlEncode(q))
	status, _, body, err := core.HTTPGet(ctx, url, map[string]string{
		"Accept": "application/vnd.github+json",
	})
	if err != nil || status != 200 {
		return nil
	}
	var out struct {
		TotalCount int `json:"total_count"`
		Items      []struct {
			HTMLURL string `json:"html_url"`
		} `json:"items"`
	}
	if json.Unmarshal(body, &out) != nil {
		return nil
	}
	t.Data = map[string]any{"total": out.TotalCount}
	for _, item := range out.Items {
		t.Hits = append(t.Hits, item.HTMLURL)
	}
	return t
}

func traceWayback(ctx context.Context, host string) *Trace {
	t := &Trace{Source: "wayback", Kind: "availability"}
	url := fmt.Sprintf("https://archive.org/wayback/available?url=%s", urlEncode(host))
	status, _, body, err := core.HTTPGet(ctx, url, nil)
	if err != nil || status != 200 {
		return nil
	}
	var out struct {
		ArchivedSnapshots struct {
			Closest struct {
				URL       string `json:"url"`
				Status    string `json:"status"`
				Timestamp string `json:"timestamp"`
			} `json:"closest"`
		} `json:"archived_snapshots"`
	}
	if json.Unmarshal(body, &out) != nil {
		return nil
	}
	if out.ArchivedSnapshots.Closest.URL != "" {
		t.Hits = append(t.Hits, out.ArchivedSnapshots.Closest.URL)
		t.Data = map[string]any{
			"timestamp": out.ArchivedSnapshots.Closest.Timestamp,
			"status":    out.ArchivedSnapshots.Closest.Status,
		}
	}
	return t
}

func traceGravatar(ctx context.Context, target string) *Trace {
	t := &Trace{Source: "gravatar", Kind: "profile"}
	if !strings.Contains(target, "@") {
		return nil
	}
	h := md5.Sum([]byte(strings.ToLower(target)))
	hexHash := hex.EncodeToString(h[:])
	url := "https://www.gravatar.com/avatar/" + hexHash + "?d=404"
	status, _, _, _ := core.HTTPGet(ctx, url, nil)
	if status == 200 {
		t.Hits = append(t.Hits, url)
	}
	return t
}

func traceHackerTarget(ctx context.Context, host string) *Trace {
	t := &Trace{Source: "hackertarget", Kind: "reverse_ip"}
	url := fmt.Sprintf("https://api.hackertarget.com/reverseiplookup/?q=%s", urlEncode(host))
	status, _, body, err := core.HTTPGet(ctx, url, nil)
	if err != nil || status != 200 {
		return nil
	}
	s := string(body)
	if strings.HasPrefix(s, "error") || strings.HasPrefix(s, "API count exceeded") {
		return nil
	}
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && strings.Contains(line, ".") {
			t.Hits = append(t.Hits, line)
			if len(t.Hits) >= 50 {
				break
			}
		}
	}
	return t
}

func urlEncode(s string) string {
	var b strings.Builder
	for _, c := range s {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~' {
			b.WriteRune(c)
		} else {
			b.WriteString(fmt.Sprintf("%%%02X", c))
		}
	}
	return b.String()
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
