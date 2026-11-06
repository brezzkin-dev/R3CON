package t34_vulnintel

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	core "github.com/brezzkin-dev/CINT/internal/universe/core"
)

const (
	nvdURL     = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=%s"
	nvdKeyword = "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=%s&resultsPerPage=20"
	epssURL    = "https://api.first.org/data/v1/epss?cve=%s"
	kevURL     = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)

type cveResult struct {
	ID          string   `json:"id"`
	Description string   `json:"description"`
	CVSS        float64  `json:"cvss_score"`
	Severity    string   `json:"cvss_severity"`
	EPSS        float64  `json:"epss,omitempty"`
	EPSSPct     float64  `json:"epss_percentile,omitempty"`
	InKEV       bool     `json:"in_cisa_kev"`
	Published   string   `json:"published,omitempty"`
	References  []string `json:"references,omitempty"`
	ExploitRefs []string `json:"exploit_refs,omitempty"`
}

var kevCache struct {
	once sync.Once
	data map[string]bool
	err  error
}

func loadKEV(ctx context.Context) (map[string]bool, error) {
	kevCache.once.Do(func() {
		kevCache.data = map[string]bool{}
		status, _, body, err := core.HTTPGet(ctx, kevURL, nil)
		if err != nil || status != 200 {
			kevCache.err = fmt.Errorf("kev http %d", status)
			return
		}
		var parsed struct {
			Vulnerabilities []struct {
				CVEID string `json:"cveID"`
			} `json:"vulnerabilities"`
		}
		if json.Unmarshal(body, &parsed) != nil {
			kevCache.err = fmt.Errorf("kev parse")
			return
		}
		for _, v := range parsed.Vulnerabilities {
			kevCache.data[v.CVEID] = true
		}
	})
	return kevCache.data, kevCache.err
}

func Lookup(cveID string) (*core.Result, error) {
	r := core.NewResult("vulnintel", cveID)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	res, err := fetchCVE(ctx, cveID)
	if err != nil {
		return r, err
	}
	if res == nil {
		r.Add(core.Finding{Tool: "vulnintel", Severity: core.SevInfo,
			Title: "CVE not found"})
		r.Finish()
		return r, nil
	}
	r.AddExtra("cve", res)

	sev := core.SevInfo
	switch {
	case res.InKEV:
		sev = core.SevCrit
	case res.CVSS >= 9.0:
		sev = core.SevCrit
	case res.CVSS >= 7.0:
		sev = core.SevHigh
	case res.CVSS >= 4.0:
		sev = core.SevMed
	}
	r.Add(core.Finding{
		Tool: "vulnintel", Severity: sev,
		Title:  cveID + fmt.Sprintf(" (CVSS %.1f)", res.CVSS),
		Detail: truncate(res.Description, 200),
		Evidence: map[string]any{
			"in_kev": res.InKEV, "epss": res.EPSS,
		},
	})
	r.Finish()
	return r, nil
}

func Batch(path string) (*core.Result, error) {
	r := core.NewResult("vulnintel-batch", path)
	f, err := os.Open(path)
	if err != nil {
		return r, err
	}
	defer f.Close()

	var ids []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line != "" && strings.HasPrefix(strings.ToUpper(line), "CVE-") {
			ids = append(ids, line)
		}
	}
	if len(ids) == 0 {
		return r, fmt.Errorf("no CVEs found in %s", path)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	results := make([]*cveResult, len(ids))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 4)
	for i, id := range ids {
		wg.Add(1)
		go func(i int, id string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			res, err := fetchCVE(ctx, id)
			if err != nil {
				core.Warnf("%s: %v", id, err)
				return
			}
			results[i] = res
		}(i, id)
	}
	wg.Wait()

	var valid []*cveResult
	crit, high := 0, 0
	for _, res := range results {
		if res == nil {
			continue
		}
		valid = append(valid, res)
		if res.InKEV || res.CVSS >= 9.0 {
			crit++
		} else if res.CVSS >= 7.0 {
			high++
		}
	}
	sort.Slice(valid, func(i, j int) bool { return valid[i].CVSS > valid[j].CVSS })
	r.AddExtra("cves", valid)
	r.AddExtra("total", len(valid))
	r.AddExtra("critical", crit)
	r.AddExtra("high", high)
	r.Add(core.Finding{
		Tool: "vulnintel", Severity: core.SevInfo,
		Title: fmt.Sprintf("%d CVEs (%d critical, %d high)", len(valid), crit, high),
	})
	r.Finish()
	return r, nil
}

func FromBanner(banner string) (*core.Result, error) {
	r := core.NewResult("vulnintel-banner", banner)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	m := regexp.MustCompile(`([A-Za-z][\w\-]+)[/\s]v?(\d+\.\d+(?:\.\d+)?)`).FindStringSubmatch(banner)
	if m == nil {
		return r, fmt.Errorf("no product/version in banner")
	}
	product := m[1]
	version := m[2]
	r.AddExtra("product", product)
	r.AddExtra("version", version)

	url := fmt.Sprintf(nvdKeyword, product)
	status, _, body, err := core.HTTPGet(ctx, url, nil)
	if err != nil || status != 200 {
		return r, fmt.Errorf("NVD search failed")
	}

	var nvd struct {
		Vulnerabilities []struct {
			CVE struct {
				ID           string `json:"id"`
				Published    string `json:"published"`
				Descriptions []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"descriptions"`
				Metrics map[string][]struct {
					CVSSData struct {
						BaseScore    float64 `json:"baseScore"`
						BaseSeverity string  `json:"baseSeverity"`
					} `json:"cvssData"`
				} `json:"metrics"`
				Configurations []struct {
					Nodes []struct {
						CPEMatch []struct {
							Criteria string `json:"criteria"`
						} `json:"cpeMatch"`
					} `json:"nodes"`
				} `json:"configurations"`
			} `json:"cve"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(body, &nvd); err != nil {
		return r, err
	}

	var matching []*cveResult
	for _, v := range nvd.Vulnerabilities {
		cve := v.CVE
		matches := versionMatchesBanner(product, version, cve.Configurations)
		if !matches {
			continue
		}
		score := 0.0
		sev := ""
		for _, group := range cve.Metrics {
			for _, m := range group {
				if m.CVSSData.BaseScore > score {
					score = m.CVSSData.BaseScore
					sev = m.CVSSData.BaseSeverity
				}
			}
		}
		desc := ""
		for _, d := range cve.Descriptions {
			if d.Lang == "en" {
				desc = d.Value
				break
			}
		}
		cr := &cveResult{
			ID: cve.ID, Description: desc,
			CVSS: score, Severity: sev, Published: cve.Published,
		}
		if epss, pct := fetchEPSS(ctx, cr.ID); epss > 0 {
			cr.EPSS = epss
			cr.EPSSPct = pct
		}
		if kev, err := loadKEV(ctx); err == nil && kev[cr.ID] {
			cr.InKEV = true
		}
		matching = append(matching, cr)
	}

	sort.Slice(matching, func(i, j int) bool { return matching[i].CVSS > matching[j].CVSS })

	for _, c := range matching {
		sev := core.SevHigh
		if c.InKEV || c.CVSS >= 9.0 {
			sev = core.SevCrit
		}
		r.Add(core.Finding{
			Tool: "vulnintel", Severity: sev,
			Title:  c.ID + fmt.Sprintf(" (CVSS %.1f)", c.CVSS),
			Detail: truncate(c.Description, 200),
			Evidence: map[string]any{
				"in_kev": c.InKEV, "epss": c.EPSS,
			},
		})
	}
	if len(matching) > 20 {
		matching = matching[:20]
	}
	r.AddExtra("matching_cves", matching)
	r.AddExtra("match_count", len(matching))
	r.Finish()
	return r, nil
}

func fetchCVE(ctx context.Context, id string) (*cveResult, error) {
	status, _, body, err := core.HTTPGet(ctx, fmt.Sprintf(nvdURL, id), nil)
	if err != nil {
		return nil, err
	}
	if status == 404 {
		return nil, nil
	}
	if status != 200 {
		return nil, fmt.Errorf("http %d", status)
	}
	var nvd struct {
		Vulnerabilities []struct {
			CVE struct {
				ID           string `json:"id"`
				Published    string `json:"published"`
				Descriptions []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"descriptions"`
				Metrics map[string][]struct {
					CVSSData struct {
						BaseScore    float64 `json:"baseScore"`
						BaseSeverity string  `json:"baseSeverity"`
					} `json:"cvssData"`
				} `json:"metrics"`
				References []struct {
					URL string `json:"url"`
				} `json:"references"`
			} `json:"cve"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(body, &nvd); err != nil {
		return nil, err
	}
	if len(nvd.Vulnerabilities) == 0 {
		return nil, nil
	}
	cve := nvd.Vulnerabilities[0].CVE
	res := &cveResult{ID: cve.ID, Published: cve.Published}
	for _, d := range cve.Descriptions {
		if d.Lang == "en" {
			res.Description = d.Value
			break
		}
	}
	for _, group := range cve.Metrics {
		for _, m := range group {
			if m.CVSSData.BaseScore > res.CVSS {
				res.CVSS = m.CVSSData.BaseScore
				res.Severity = m.CVSSData.BaseSeverity
			}
		}
	}
	for _, ref := range cve.References {
		res.References = append(res.References, ref.URL)
		if strings.Contains(ref.URL, "exploit-db") ||
			(strings.Contains(ref.URL, "github.com/") && strings.Contains(ref.URL, "PoC")) {
			res.ExploitRefs = append(res.ExploitRefs, ref.URL)
		}
	}
	if epss, pct := fetchEPSS(ctx, res.ID); epss > 0 {
		res.EPSS = epss
		res.EPSSPct = pct
	}
	if kev, err := loadKEV(ctx); err == nil && kev[res.ID] {
		res.InKEV = true
	}
	return res, nil
}

func fetchEPSS(ctx context.Context, id string) (float64, float64) {
	status, _, body, err := core.HTTPGet(ctx, fmt.Sprintf(epssURL, id), nil)
	if err != nil || status != 200 {
		return 0, 0
	}
	var ep struct {
		Data []struct {
			EPSS string `json:"epss"`
			Perc string `json:"percentile"`
		} `json:"data"`
	}
	if json.Unmarshal(body, &ep) != nil || len(ep.Data) == 0 {
		return 0, 0
	}
	e, _ := strconv.ParseFloat(ep.Data[0].EPSS, 64)
	p, _ := strconv.ParseFloat(ep.Data[0].Perc, 64)
	return e, p
}

func versionMatchesBanner(product, version string, configs []struct {
	Nodes []struct {
		CPEMatch []struct {
			Criteria string `json:"criteria"`
		} `json:"cpeMatch"`
	} `json:"nodes"`
}) bool {
	productLower := strings.ToLower(product)
	for _, cfg := range configs {
		for _, node := range cfg.Nodes {
			for _, cpe := range node.CPEMatch {
				crit := cpe.Criteria
				parts := strings.Split(crit, ":")
				if len(parts) < 6 {
					continue
				}
				cpeProduct := strings.ToLower(parts[4])
				cpeVersion := parts[5]
				if !strings.Contains(productLower, cpeProduct) && !strings.Contains(cpeProduct, productLower) {
					continue
				}
				if cpeVersion == "*" || cpeVersion == "-" {
					return true
				}
				if versionCompare(version, cpeVersion) == 0 {
					return true
				}
			}
		}
	}
	return false
}

func versionCompare(a, b string) int {
	pa := strings.Split(a, ".")
	pb := strings.Split(b, ".")
	n := len(pa)
	if len(pb) > n {
		n = len(pb)
	}
	for i := 0; i < n; i++ {
		var ai, bi int
		if i < len(pa) {
			ai, _ = strconv.Atoi(pa[i])
		}
		if i < len(pb) {
			bi, _ = strconv.Atoi(pb[i])
		}
		if ai < bi {
			return -1
		}
		if ai > bi {
			return 1
		}
	}
	return 0
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
