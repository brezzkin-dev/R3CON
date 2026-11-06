package t07_phototrace

import (
	"image"
	"math"
)

type NoiseResult struct {
	BlockVariances     []float64 `json:"block_variances"`
	MeanVariance       float64   `json:"mean_variance"`
	StdevVariance      float64   `json:"stdev_variance"`
	HeterogeneityScore float64   `json:"heterogeneity_score"`
}

func NoiseVariance(img image.Image) *NoiseResult {
	b := img.Bounds()
	const block = 16
	var blockVars []float64

	for y := b.Min.Y; y+block <= b.Max.Y; y += block {
		for x := b.Min.X; x+block <= b.Max.X; x += block {
			var residuals []float64
			for yy := y; yy < y+block; yy++ {
				for xx := x; xx < x+block; xx++ {
					r, g, bb, _ := img.At(xx, yy).RGBA()
					lum := 0.299*float64(r>>8) + 0.587*float64(g>>8) + 0.114*float64(bb>>8)
					var nsum float64
					var nn int
					for dy := -1; dy <= 1; dy++ {
						for dx := -1; dx <= 1; dx++ {
							if dx == 0 && dy == 0 {
								continue
							}
							nx, ny := xx+dx, yy+dy
							if nx < b.Min.X || nx >= b.Max.X || ny < b.Min.Y || ny >= b.Max.Y {
								continue
							}
							nr, ng, nb, _ := img.At(nx, ny).RGBA()
							nl := 0.299*float64(nr>>8) + 0.587*float64(ng>>8) + 0.114*float64(nb>>8)
							nsum += nl
							nn++
						}
					}
					if nn > 0 {
						residuals = append(residuals, lum-nsum/float64(nn))
					}
				}
			}
			if len(residuals) < 2 {
				continue
			}
			var mean float64
			for _, v := range residuals {
				mean += v
			}
			mean /= float64(len(residuals))
			var variance float64
			for _, v := range residuals {
				d := v - mean
				variance += d * d
			}
			variance /= float64(len(residuals))
			blockVars = append(blockVars, variance)
		}
	}

	if len(blockVars) == 0 {
		return nil
	}
	var sum float64
	for _, v := range blockVars {
		sum += v
	}
	mean := sum / float64(len(blockVars))
	var varSum float64
	for _, v := range blockVars {
		d := v - mean
		varSum += d * d
	}
	stdev := math.Sqrt(varSum / float64(len(blockVars)))
	score := 0.0
	if mean > 0.001 {
		score = stdev / mean
	}
	report := blockVars
	if len(report) > 200 {
		report = report[:200]
	}
	return &NoiseResult{
		BlockVariances:     report,
		MeanVariance:       roundf(mean, 4),
		StdevVariance:      roundf(stdev, 4),
		HeterogeneityScore: roundf(score, 4),
	}
}
