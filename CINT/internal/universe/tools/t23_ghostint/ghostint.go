package t23_ghostint

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"sync"

	core "github.com/brezzkin-dev/CINT/internal/universe/core"
)

const (
	urlhausAPI   = "https://urlhaus-api.abuse.ch/v1/host/"
	threatfoxAPI = "https://threatfox-api.abuse.ch/api/v1/"
	feodoURL     = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
	openphishURL = "https://openphish.com/feed.txt"
	geoAPI       = "http://ip-api.com/json/%s?fields=status,country,countryCode,regionName,city,isp,org,as,query,proxy,hosting"
)

type Intel struct {
	IOC         string         `json:"ioc"`
	Kind        string         `json:"kind"`
	Sources     []string       `json:"sources"`
	URLHaus     map[string]any `json:"urlhaus,omitempty"`
	ThreatFox   map[string]any `json:"threatfox,omitempty"`
	Geo         map[string]any `json:"geo,omitempty"`
	FeodoListed bool           `json:"feodo_listed"`
	OpenPhish   bool           `json:"openphish"`
	Score       int            `json:"score"`
	Reasons     []string       `json:"reasons"`
}

type feedCache struct {
	once sync.Once
	data []map[string]any
	err  error
}

var feodoCache feedCache
var phishCache struct {
	once sync.Once
	set  map[string]bool
}

func loadFeodo(ctx context.Context) ([]map[string]any, error) {
	feodoCache.once.Do(func() {
		status, _, body, err := core.HTTPGet(ctx, feodoURL, nil)
		if err != nil || status != 200 {
			feodoCache.err = fmt.Errorf("feodo http %d", status)
			return
		}
		if err := json.Unmarshal(body, &feodoCache.data); err != nil {
			feodoCache.err = err
		}
	})
	return feodoCache.data, feodoCache.err
}

func loadOpenPhish(ctx context.Context) map[string]bool {
	phishCache.once.Do(func() {
		phishCache.set = map[string]bool{}
		status, _, body, err := core.HTTPGet(ctx, openphishURL, nil)
		if err != nil || status != 200 {
			return
		}
		for _, line := range strings.Split(string(body), "\n") {
			line = strings.TrimSpace(line)
			if line != "" {
				phishCache.set[line] = true
			}
		}
	})
	return phishCache.set
}

func Run(iocs []string, feed string) (*core.Result, error) {
	r := core.NewResult("ghostint", strings.Join(iocs, ","))
	ctx := context.Background()

	feodoList, _ := loadFeodo(ctx)
	feodoSet := map[string]bool{}
	for _, e := range feodoList {
		if ip, ok := e["ip_address"].(string); ok {
			feodoSet[ip] = true
		}
	}
	r.AddExtra("feodo_count", len(feodoSet))

	phishSet := loadOpenPhish(ctx)
	r.AddExtra("openphish_count", len(phishSet))

	if feed == "feodo" || feed == "all" {
		r.AddExtra("feodo_sample", firstN(feodoList, 50))
	}
	if feed == "openphish" || feed == "all" {
		keys := make([]string, 0, len(phishSet))
		for k := range phishSet {
			keys = append(keys, k)
			if len(keys) >= 50 {
				break
			}
		}
		r.AddExtra("openphish_sample", keys)
	}

	if len(iocs) == 0 {
		r.Add(core.Finding{Tool: "ghostint", Severity: core.SevInfo,
			Title: fmt.Sprintf("Bulk feed loaded: %d feodo, %d phish",
				len(feodoSet), len(phishSet))})
		r.Finish()
		return r, nil
	}

	var results []Intel
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 6)

	for _, raw := range iocs {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		wg.Add(1)
		go func(ioc string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			intel := lookupAll(ctx, ioc, feodoSet, phishSet)
			mu.Lock()
			results = append(results, intel)
			mu.Unlock()
		}(raw)
	}
	wg.Wait()

	for _, i := range results {
		sev := core.SevInfo
		switch {
		case i.Score >= 80:
			sev = core.SevCrit
		case i.Score >= 50:
			sev = core.SevHigh
		case i.Score >= 25:
			sev = core.SevMed
		}
		if sev != core.SevInfo {
			r.Add(core.Finding{
				Tool: "ghostint", Severity: sev,
				Title:    "IOC " + i.IOC,
				Detail:   strings.Join(i.Reasons, ", "),
				Evidence: map[string]any{"sources": i.Sources, "score": i.Score},
			})
		}
	}
	r.AddExtra("intel", results)
	r.Finish()
	return r, nil
}

func lookupAll(ctx context.Context, ioc string, feodoSet, phishSet map[string]bool) Intel {
	intel := Intel{IOC: ioc, Kind: string(core.Classify(ioc))}
	intel.Sources = []string{}
	intel.Reasons = []string{}

	switch core.Classify(ioc) {
	case core.IOCIPv4:
		intel.Geo = lookupGeo(ctx, ioc)
		intel.ThreatFox = lookupThreatFox(ctx, ioc)
		intel.FeodoListed = feodoSet[ioc]

	case core.IOCDomain:
		intel.URLHaus = lookupURLHaus(ctx, ioc)
		intel.ThreatFox = lookupThreatFox(ctx, ioc)

	case core.IOCURL:
		intel.ThreatFox = lookupThreatFox(ctx, ioc)
		intel.OpenPhish = phishSet[ioc]

	case core.IOCMD5, core.IOCSHA1, core.IOCSHA256:
		intel.ThreatFox = lookupThreatFox(ctx, ioc)
	}

	if intel.URLHaus != nil {
		if urls, ok := intel.URLHaus["urls"].([]any); ok && len(urls) > 0 {
			intel.Sources = append(intel.Sources, "urlhaus")
			intel.Score += 30
			intel.Reasons = append(intel.Reasons, fmt.Sprintf("URLhaus %d URLs", len(urls)))
		}
	}
	if intel.ThreatFox != nil {
		if data, ok := intel.ThreatFox["data"].([]any); ok && len(data) > 0 {
			intel.Sources = append(intel.Sources, "threatfox")
			intel.Score += 40
			intel.Reasons = append(intel.Reasons, fmt.Sprintf("ThreatFox %d records", len(data)))
		}
	}
	if intel.FeodoListed {
		intel.Sources = append(intel.Sources, "feodo")
		intel.Score += 50
		intel.Reasons = append(intel.Reasons, "Feodo C2 blocklist")
	}
	if intel.OpenPhish {
		intel.Sources = append(intel.Sources, "openphish")
		intel.Score += 40
		intel.Reasons = append(intel.Reasons, "OpenPhish URL blocklist")
	}
	if intel.Geo != nil {
		if b, ok := intel.Geo["proxy"].(bool); ok && b {
			intel.Score += 10
			intel.Reasons = append(intel.Reasons, "proxy/VPN")
		}
		if b, ok := intel.Geo["hosting"].(bool); ok && b {
			intel.Score += 5
			intel.Reasons = append(intel.Reasons, "datacenter")
		}
	}

	if len(intel.Sources) >= 2 {
		intel.Score += 20
		intel.Reasons = append(intel.Reasons, "multi-source corroboration")
	}
	return intel
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
	return out
}

func lookupURLHaus(ctx context.Context, host string) map[string]any {
	body := []byte(url.Values{"host": []string{host}}.Encode())
	status, resp, err := core.HTTPPost(ctx, urlhausAPI, "application/x-www-form-urlencoded", body, nil)
	if err != nil || status != 200 {
		return nil
	}
	var out map[string]any
	if json.Unmarshal(resp, &out) != nil {
		return nil
	}
	return out
}

func lookupThreatFox(ctx context.Context, ioc string) map[string]any {
	body, _ := json.Marshal(map[string]any{"query": "search_ioc", "search_term": ioc})
	status, resp, err := core.HTTPPost(ctx, threatfoxAPI, "application/json", body, nil)
	if err != nil || status != 200 {
		return nil
	}
	var out map[string]any
	if json.Unmarshal(resp, &out) != nil {
		return nil
	}
	return out
}

func firstN(list []map[string]any, n int) []map[string]any {
	if len(list) <= n {
		return list
	}
	return list[:n]
}
