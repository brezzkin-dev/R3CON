package vulnintel

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"sync"

	core "github.com/brezzkin-dev/CINT/internal/cyber/core"
)

const (
	nvdURL  = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=%s"
	epssURL = "https://api.first.org/data/v1/epss?cve=%s"
	kevURL  = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)

type nvdResponse struct {
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

var kevCache struct {
	once sync.Once
	set  map[string]bool
}

func loadKEV(ctx context.Context) map[string]bool {
	kevCache.once.Do(func() {
		kevCache.set = map[string]bool{}
		status, _, body, err := core.HTTPGet(ctx, kevURL, nil)
		if err != nil || status != 200 {
			return
		}
		var k struct {
			Vulnerabilities []struct {
				CVEID string `json:"cveID"`
			} `json:"vulnerabilities"`
		}
		if json.Unmarshal(body, &k) != nil {
			return
		}
		for _, v := range k.Vulnerabilities {
			kevCache.set[v.CVEID] = true
		}
	})
	return kevCache.set
}

func LookupCVE(ctx context.Context, cveID string) *core.Result {
	r := core.NewResult("vulnintel", cveID)
	status, _, body, err := core.HTTPGet(ctx, fmt.Sprintf(nvdURL, cveID), nil)
	if err != nil || status != 200 {
		r.Add(core.Finding{Tool: "vulnintel", Severity: core.SevHigh,
			Title:  "NVD lookup failed",
			Detail: fmt.Sprintf("status=%d err=%v", status, err)})
		r.Finish()
		return r
	}
	var nvd nvdResponse
	if json.Unmarshal(body, &nvd) != nil || len(nvd.Vulnerabilities) == 0 {
		r.Add(core.Finding{Tool: "vulnintel", Severity: core.SevHigh, Title: "CVE not found"})
		r.Finish()
		return r
	}
	cve := nvd.Vulnerabilities[0].CVE

	desc := ""
	for _, d := range cve.Descriptions {
		if d.Lang == "en" {
			desc = d.Value
			break
		}
	}
	r.AddExtra("description", desc)

	var score float64
	for _, groups := range cve.Metrics {
		for _, m := range groups {
			if m.CVSSData.BaseScore > score {
				score = m.CVSSData.BaseScore
			}
		}
	}
	r.AddExtra("cvss_score", score)

	var refs []string
	for _, ref := range cve.References {
		refs = append(refs, ref.URL)
	}
	r.AddExtra("references", refs)

	if st2, _, b2, _ := core.HTTPGet(ctx, fmt.Sprintf(epssURL, cveID), nil); st2 == 200 {
		var ep struct {
			Data []struct {
				EPSS string `json:"epss"`
				Perc string `json:"percentile"`
			} `json:"data"`
		}
		if json.Unmarshal(b2, &ep) == nil && len(ep.Data) > 0 {
			r.AddExtra("epss", ep.Data[0].EPSS)
			r.AddExtra("epss_percentile", ep.Data[0].Perc)
		}
	}

	if loadKEV(ctx)[cveID] {
		r.AddExtra("in_cisa_kev", true)
		r.Add(core.Finding{Tool: "vulnintel", Severity: core.SevCrit,
			Title: "In CISA KEV catalog", Detail: desc})
	} else if score >= 9.0 {
		r.Add(core.Finding{Tool: "vulnintel", Severity: core.SevCrit,
			Title:  fmt.Sprintf("CVSS %.1f critical", score),
			Detail: desc})
	} else if score >= 7.0 {
		r.Add(core.Finding{Tool: "vulnintel", Severity: core.SevHigh,
			Title:  fmt.Sprintf("CVSS %.1f high", score),
			Detail: desc})
	}
	r.Finish()
	return r
}

func ScanPackages(ctx context.Context) *core.Result {
	r := core.NewResult("vulnintel-pkgs", "local")
	out := scanDpkg()
	if out == "" {
		out = scanRPM()
	}
	if out == "" {
		out = scanAPK()
	}
	if out == "" {
		r.Add(core.Finding{Tool: "vulnintel", Severity: core.SevHigh,
			Title: "no supported package manager found"})
		r.Finish()
		return r
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	r.AddExtra("package_count", len(lines))
	r.AddExtra("packages", lines)
	r.Finish()
	return r
}

func scanDpkg() string {
	out, err := exec.Command("dpkg-query", "-W", "-f=${Package} ${Version}\n").Output()
	if err != nil {
		return ""
	}
	return string(out)
}

func scanRPM() string {
	out, err := exec.Command("rpm", "-qa", "--qf", "%{NAME} %{VERSION}-%{RELEASE}\n").Output()
	if err != nil {
		return ""
	}
	return string(out)
}

func scanAPK() string {
	out, err := exec.Command("apk", "info", "-v").Output()
	if err != nil {
		return ""
	}
	return string(out)
}
