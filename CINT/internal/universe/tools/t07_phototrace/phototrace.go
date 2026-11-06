package t07_phototrace

import (
	"fmt"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"os"
	"strings"

	core "github.com/brezzkin-dev/CINT/internal/universe/core"
)

type Options struct {
	Deep bool
}

type Report struct {
	File          string          `json:"file"`
	Format        string          `json:"format"`
	Dimensions    [2]int          `json:"dimensions"`
	Bytes         int64           `json:"bytes"`
	EXIF          map[string]any  `json:"exif,omitempty"`
	DQT           []int           `json:"dqt,omitempty"`
	ELA           *ELAResult      `json:"ela,omitempty"`
	Noise         *NoiseResult    `json:"noise,omitempty"`
	Chroma        *ChromaResult   `json:"chroma,omitempty"`
	DoubleJPEG    *DoubleResult   `json:"double_jpeg,omitempty"`
	CopyMove      *CopyMoveResult `json:"copy_move,omitempty"`
	Ghost         []GhostResult   `json:"ghost,omitempty"`
	Inconsistency []string        `json:"inconsistencies,omitempty"`
	Score         int             `json:"tamper_score"`
	Verdict       string          `json:"verdict"`
}

func Run(path string, opts Options) (*core.Result, error) {
	r := core.NewResult("phototrace", path)

	stat, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	img, fmtName, err := image.Decode(f)
	if err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	bounds := img.Bounds()

	report := &Report{
		File:       path,
		Format:     fmtName,
		Dimensions: [2]int{bounds.Dx(), bounds.Dy()},
		Bytes:      stat.Size(),
	}
	r.AddExtra("format", fmtName)
	r.AddExtra("width", bounds.Dx())
	r.AddExtra("height", bounds.Dy())
	r.AddExtra("bytes", stat.Size())

	rawBytes, _ := os.ReadFile(path)

	exif := ParseEXIF(rawBytes)
	if exif != nil {
		report.EXIF = exif
		r.AddExtra("exif", exif)
		checkEXIFConsistency(exif, r, &report.Inconsistency)
	}

	if fmtName == "jpeg" {
		dqt := ParseDQT(rawBytes)
		if len(dqt) > 0 {
			report.DQT = dqt
			r.AddExtra("dqt", dqt)
			checkDQTAnomalies(dqt, r, &report.Inconsistency)
		}
	}

	ela, err := ELA(path, img)
	if err == nil && ela != nil {
		report.ELA = ela
		r.AddExtra("ela", ela)
		if ela.AnomalousRatio > 0.15 {
			r.Add(core.Finding{
				Tool: "phototrace", Severity: core.SevHigh,
				Title: "ELA anomaly detected",
				Detail: fmt.Sprintf("%.1f%% pixels anomalous (heuristic — likely splice/airbrush)",
					ela.AnomalousRatio*100),
				Evidence: map[string]any{
					"anomalous_ratio": ela.AnomalousRatio,
					"max_diff":        ela.MaxDiff,
					"mean_diff":       ela.MeanDiff,
				},
			})
			report.Score += 30
		}
	}

	noise := NoiseVariance(img)
	report.Noise = noise
	r.AddExtra("noise", noise)
	if noise != nil && noise.HeterogeneityScore > 0.5 {
		r.Add(core.Finding{
			Tool: "phototrace", Severity: core.SevHigh,
			Title: "Noise variance heterogeneous",
			Detail: fmt.Sprintf("score %.2f — inconsistent noise across regions (heuristic)",
				noise.HeterogeneityScore),
			Evidence: map[string]any{"score": noise.HeterogeneityScore},
		})
		report.Score += 25
	}

	chroma := ChromaticAberration(img)
	report.Chroma = chroma
	r.AddExtra("chroma", chroma)
	if chroma != nil && chroma.ChannelDiscrepancy > 0.4 {
		r.Add(core.Finding{
			Tool: "phototrace", Severity: core.SevMed,
			Title:    "Chromatic aberration inconsistent",
			Detail:   fmt.Sprintf("RGB edge misalignment %.2f (heuristic)", chroma.ChannelDiscrepancy),
			Evidence: map[string]any{"discrepancy": chroma.ChannelDiscrepancy},
		})
		report.Score += 15
	}

	if opts.Deep {
		if fmtName == "jpeg" {
			dj := DetectDoubleJPEG(img, report.DQT)
			report.DoubleJPEG = dj
			r.AddExtra("double_jpeg", dj)
			if dj != nil && dj.LikelyDouble {
				r.Add(core.Finding{
					Tool: "phototrace", Severity: core.SevHigh,
					Title:    "Double JPEG compression suspected",
					Detail:   "AC coefficient histogram shows double-peak pattern (heuristic)",
					Evidence: map[string]any{"peak_ratio": dj.PeakRatio, "confidence": dj.Confidence},
				})
				report.Score += 25
			}
		}

		cm := DetectCopyMove(img)
		report.CopyMove = cm
		r.AddExtra("copy_move", cm)
		if cm != nil && len(cm.Regions) > 0 {
			r.Add(core.Finding{
				Tool: "phototrace", Severity: core.SevHigh,
				Title:    fmt.Sprintf("Copy-move: %d duplicate regions", len(cm.Regions)),
				Detail:   "identical block hashes found at multiple positions (heuristic)",
				Evidence: map[string]any{"regions": cm.Regions},
			})
			report.Score += 35
		}

		ghosts := JPEGGhost(img)
		report.Ghost = ghosts
		r.AddExtra("ghost", ghosts)
		for _, g := range ghosts {
			if g.AnomalousCells > g.TotalCells/10 {
				r.Add(core.Finding{
					Tool: "phototrace", Severity: core.SevMed,
					Title: fmt.Sprintf("JPEG ghost at Q=%d", g.Quality),
					Detail: fmt.Sprintf("%d/%d cells show prior-compression mismatch (heuristic)",
						g.AnomalousCells, g.TotalCells),
					Evidence: map[string]any{"quality": g.Quality, "anomalous": g.AnomalousCells},
				})
				report.Score += 10
			}
		}
	}

	switch {
	case report.Score >= 60:
		report.Verdict = "heuristic indicators: strong (multiple signals — validate manually)"
	case report.Score >= 30:
		report.Verdict = "heuristic indicators: moderate (some signals — validate manually)"
	case report.Score >= 10:
		report.Verdict = "heuristic indicators: minor"
	default:
		report.Verdict = "heuristic indicators: none observed"
	}

	r.AddExtra("report", report)
	r.AddExtra("tamper_score", report.Score)
	r.AddExtra("verdict", report.Verdict)
	r.AddExtra("verdict_note",
		"heuristic signals only — not forensic proof. Recompression, resizing, "+
			"and normal editing produce identical patterns. Cross-check with the "+
			"original source and validate manually.")
	r.AddExtra("inconsistencies", report.Inconsistency)

	if len(report.Inconsistency) > 0 {
		r.Add(core.Finding{
			Tool: "phototrace", Severity: core.SevMed,
			Title:  "EXIF / DQT inconsistencies",
			Detail: strings.Join(report.Inconsistency, "; "),
		})
	}

	r.Finish()
	return r, nil
}

func checkEXIFConsistency(exif map[string]any, r *core.Result, out *[]string) {
	if sw, ok := exif["Software"].(string); ok && sw != "" {
		low := strings.ToLower(sw)
		if strings.Contains(low, "photoshop") ||
			strings.Contains(low, "gimp") ||
			strings.Contains(low, "lightroom") ||
			strings.Contains(low, "pixlr") {
			*out = append(*out, "edited with "+sw)
			r.Add(core.Finding{
				Tool: "phototrace", Severity: core.SevMed,
				Title: "Image edited with " + sw,
			})
		}
	}
	if dt, ok := exif["DateTime"].(string); ok {
		if dt2, ok2 := exif["DateTimeOriginal"].(string); ok2 && dt != dt2 {
			*out = append(*out, "DateTime != DateTimeOriginal")
		}
	}
}

func checkDQTAnomalies(dqt []int, r *core.Result, out *[]string) {
	if len(dqt) < 64 {
		return
	}
	var sum int
	for _, v := range dqt[:64] {
		sum += v
	}
	avg := sum / 64
	if avg < 2 {
		*out = append(*out, "extremely high quality (avg DQT < 2)")
	} else if avg > 40 {
		*out = append(*out, "very low quality (avg DQT > 40) — heavy compression")
	}
	if dqt[0] > 30 {
		*out = append(*out, "DC coefficient unusually large")
	}
}

func sortRegionsByConfidence(rs []Region) {
	for i := 1; i < len(rs); i++ {
		for j := i; j > 0 && rs[j].Score > rs[j-1].Score; j-- {
			rs[j], rs[j-1] = rs[j-1], rs[j]
		}
	}
}
