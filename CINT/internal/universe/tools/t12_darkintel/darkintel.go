package t12_darkintel

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	core "github.com/brezzkin-dev/CINT/internal/universe/core"
)

const (
	urlhausAPI   = "https://urlhaus-api.abuse.ch/v1/host/"
	threatfoxAPI = "https://threatfox-api.abuse.ch/api/v1/"
	feodoURL     = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
)

func Run(ioc, feed string) (*core.Result, error) {
	r := core.NewResult("darkintel", firstNonEmpty(ioc, feed))
	ctx := context.Background()

	if feed == "feodo" {
		return runFeodo(ctx, r)
	}
	if feed == "urlhaus" && ioc != "" {
		return runURLhaus(ctx, ioc, r)
	}
	if feed == "threatfox" && ioc != "" {
		return runThreatFox(ctx, ioc, r)
	}

	if ioc == "" {
		r.Add(core.Finding{Tool: "darkintel", Severity: core.SevHigh,
			Title: "no IOC or feed specified"})
		r.Finish()
		return r, nil
	}
	kind := core.Classify(ioc)
	r.AddExtra("ioc_kind", string(kind))
	switch kind {
	case core.IOCIPv4, core.IOCDomain, core.IOCURL:
		runThreatFox(ctx, ioc, r)
		if kind == core.IOCDomain {
			runURLhaus(ctx, ioc, r)
		}
	case core.IOCMD5, core.IOCSHA1, core.IOCSHA256:
		runThreatFox(ctx, ioc, r)
	}

	r.Finish()
	return r, nil
}

func runThreatFox(ctx context.Context, ioc string, r *core.Result) (*core.Result, error) {
	body, _ := json.Marshal(map[string]any{"query": "search_ioc", "search_term": ioc})
	status, resp, err := core.HTTPPost(ctx, threatfoxAPI, "application/json", body, nil)
	if err != nil {
		return r, err
	}
	if status != 200 {
		return r, fmt.Errorf("threatfox http %d", status)
	}
	var out map[string]any
	if json.Unmarshal(resp, &out) != nil {
		return r, nil
	}
	r.AddExtra("threatfox", out)
	if data, ok := out["data"].([]any); ok && len(data) > 0 {
		r.Add(core.Finding{
			Tool: "darkintel", Severity: core.SevCrit,
			Title:    "ThreatFox match",
			Detail:   fmt.Sprintf("%d records for %s", len(data), ioc),
			Evidence: map[string]any{"first": data[0]},
		})
	}
	return r, nil
}

func runURLhaus(ctx context.Context, host string, r *core.Result) (*core.Result, error) {
	body := []byte(url.Values{"host": []string{host}}.Encode())
	status, resp, err := core.HTTPPost(ctx, urlhausAPI, "application/x-www-form-urlencoded", body, nil)
	if err != nil {
		return r, err
	}
	if status != 200 {
		return r, fmt.Errorf("urlhaus http %d", status)
	}
	var out map[string]any
	if json.Unmarshal(resp, &out) != nil {
		return r, nil
	}
	r.AddExtra("urlhaus", out)
	if urls, ok := out["urls"].([]any); ok && len(urls) > 0 {
		r.Add(core.Finding{
			Tool: "darkintel", Severity: core.SevCrit,
			Title:  "URLhaus match",
			Detail: fmt.Sprintf("%d malicious URLs for %s", len(urls), host),
		})
	}
	return r, nil
}

func runFeodo(ctx context.Context, r *core.Result) (*core.Result, error) {
	status, _, body, err := core.HTTPGet(ctx, feodoURL, nil)
	if err != nil || status != 200 {
		return r, fmt.Errorf("feodo http %d", status)
	}
	var out []map[string]any
	if json.Unmarshal(body, &out) != nil {
		return r, nil
	}
	r.AddExtra("feodo_count", len(out))
	if len(out) > 0 {
		r.Add(core.Finding{
			Tool: "darkintel", Severity: core.SevInfo,
			Title:  fmt.Sprintf("Feodo C2 blocklist: %d IPs", len(out)),
			Detail: "fetched current botnet C2 list",
		})
		keep := out
		if len(keep) > 100 {
			keep = keep[:100]
		}
		r.AddExtra("feodo_sample", keep)
	}
	return r, nil
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

var _ = strings.TrimSpace
