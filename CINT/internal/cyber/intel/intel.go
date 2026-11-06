package intel

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"sync"

	core "github.com/brezzkin-dev/CINT/internal/cyber/core"
)

const (
	urlhausHost  = "https://urlhaus-api.abuse.ch/v1/host/"
	threatfoxAPI = "https://threatfox-api.abuse.ch/api/v1/"
	bazaarAPI    = "https://mb-api.abuse.ch/api/v1/"
	openphishURL = "https://openphish.com/feed.txt"
	geoAPI       = "http://ip-api.com/json/%s?fields=status,country,countryCode,regionName,city,isp,org,as,query"
)

type entry struct {
	IOC       string         `json:"ioc"`
	Kind      string         `json:"kind"`
	Geo       map[string]any `json:"geo,omitempty"`
	URLHaus   map[string]any `json:"urlhaus,omitempty"`
	ThreatFox map[string]any `json:"threatfox,omitempty"`
	Bazaar    map[string]any `json:"bazaar,omitempty"`
	OpenPhish bool           `json:"openphish"`
	Score     int            `json:"score"`
	Reasons   []string       `json:"reasons,omitempty"`
}

var openphishCache struct {
	once   sync.Once
	loaded map[string]bool
}

func loadOpenPhish(ctx context.Context) map[string]bool {
	openphishCache.once.Do(func() {
		openphishCache.loaded = map[string]bool{}
		status, _, body, err := core.HTTPGet(ctx, openphishURL, nil)
		if err != nil || status != 200 {
			return
		}
		for _, l := range strings.Split(string(body), "\n") {
			if l = strings.TrimSpace(l); l != "" {
				openphishCache.loaded[l] = true
			}
		}
	})
	return openphishCache.loaded
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
	status, resp, err := core.HTTPPost(ctx, urlhausHost, "application/x-www-form-urlencoded", body, nil)
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

func lookupBazaar(ctx context.Context, hash string) map[string]any {
	body := []byte(url.Values{"query": []string{"get_info"}, "hash": []string{hash}}.Encode())
	status, resp, err := core.HTTPPost(ctx, bazaarAPI, "application/x-www-form-urlencoded", body, nil)
	if err != nil || status != 200 {
		return nil
	}
	var out map[string]any
	if json.Unmarshal(resp, &out) != nil {
		return nil
	}
	return out
}

func score(e *entry) {
	if uh, ok := e.URLHaus["urls"]; ok {
		if urls, ok := uh.([]any); ok && len(urls) > 0 {
			e.Score += 40
			e.Reasons = append(e.Reasons, fmt.Sprintf("URLhaus: %d URLs", len(urls)))
		}
	}
	if tf, ok := e.ThreatFox["data"].([]any); ok && len(tf) > 0 {
		e.Score += 60
		e.Reasons = append(e.Reasons, fmt.Sprintf("ThreatFox: %d matches", len(tf)))
	}
	if bz, ok := e.Bazaar["data"].([]any); ok && len(bz) > 0 {
		e.Score += 70
		e.Reasons = append(e.Reasons, fmt.Sprintf("MalwareBazaar: %d samples", len(bz)))
	}
	if e.OpenPhish {
		e.Score += 50
		e.Reasons = append(e.Reasons, "OpenPhish")
	}
	if geo, ok := e.Geo["countryCode"].(string); ok && geo == "TOR" {
		e.Score += 20
		e.Reasons = append(e.Reasons, "TOR exit")
	}
}

func Enrich(ctx context.Context, iocs []string) *core.Result {
	r := core.NewResult("intel", strings.Join(iocs, ","))
	_ = loadOpenPhish(ctx)

	type task struct {
		idx  int
		ioc  string
		kind core.IOCType
	}
	var tasks []task
	for _, raw := range iocs {
		t := task{ioc: strings.TrimSpace(raw), kind: core.Classify(raw)}
		if t.ioc == "" || t.kind == core.IOCUnknown {
			continue
		}
		tasks = append(tasks, t)
	}
	entries := make([]entry, len(tasks))

	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	for i, t := range tasks {
		wg.Add(1)
		go func(i int, t task) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			e := entry{IOC: t.ioc, Kind: string(t.kind)}
			switch t.kind {
			case core.IOCIPv4:
				e.Geo = lookupGeo(ctx, t.ioc)
				e.ThreatFox = lookupThreatFox(ctx, t.ioc)
			case core.IOCDomain:
				e.URLHaus = lookupURLHaus(ctx, t.ioc)
				e.ThreatFox = lookupThreatFox(ctx, t.ioc)
			case core.IOCURL:
				e.ThreatFox = lookupThreatFox(ctx, t.ioc)
				op := loadOpenPhish(ctx)
				e.OpenPhish = op[t.ioc]
			case core.IOCMD5, core.IOCSHA1, core.IOCSHA256:
				e.ThreatFox = lookupThreatFox(ctx, t.ioc)
				e.Bazaar = lookupBazaar(ctx, t.ioc)
			}
			score(&e)
			entries[i] = e
		}(i, t)
	}
	wg.Wait()

	for _, e := range entries {
		sev := core.SevInfo
		switch {
		case e.Score >= 70:
			sev = core.SevCrit
		case e.Score >= 40:
			sev = core.SevHigh
		case e.Score >= 20:
			sev = core.SevMed
		}
		if sev != core.SevInfo {
			r.Add(core.Finding{
				Tool: "intel", Severity: sev,
				Title:    "IOC: " + e.IOC,
				Detail:   strings.Join(e.Reasons, ", "),
				Evidence: map[string]any{"kind": e.Kind, "score": e.Score},
			})
		}
	}
	r.AddExtra("entries", entries)
	r.Finish()
	return r
}
