package t07_phototrace

import (
	"bytes"
	"image"
	"image/jpeg"
	"math"
)

type GhostResult struct {
	Quality        int     `json:"quality"`
	AnomalousCells int     `json:"anomalous_cells"`
	TotalCells     int     `json:"total_cells"`
	MaxCellDiff    float64 `json:"max_cell_diff"`
}

func JPEGGhost(img image.Image) []GhostResult {
	qualities := []int{50, 60, 70, 75, 80, 85, 90, 95}
	b := img.Bounds()
	const cell = 32
	cols := b.Dx() / cell
	rows := b.Dy() / cell
	totalCells := cols * rows
	if totalCells < 4 {
		return nil
	}

	var out []GhostResult
	for _, q := range qualities {
		buf := &bytes.Buffer{}
		if err := jpeg.Encode(buf, img, &jpeg.Options{Quality: q}); err != nil {
			continue
		}
		recompressed, err := jpeg.Decode(buf)
		if err != nil {
			continue
		}
		var cellDiffs []float64
		for cy := 0; cy < rows; cy++ {
			for cx := 0; cx < cols; cx++ {
				var sum float64
				var count int
				for yy := cy * cell; yy < (cy+1)*cell; yy++ {
					for xx := cx * cell; xx < (cx+1)*cell; xx++ {
						r1, g1, b1, _ := img.At(b.Min.X+xx, b.Min.Y+yy).RGBA()
						r2, g2, b2, _ := recompressed.At(b.Min.X+xx, b.Min.Y+yy).RGBA()
						sum += math.Abs(float64(r1>>8)-float64(r2>>8)) +
							math.Abs(float64(g1>>8)-float64(g2>>8)) +
							math.Abs(float64(b1>>8)-float64(b2>>8))
						count++
					}
				}
				cellDiffs = append(cellDiffs, sum/float64(count*3))
			}
		}
		median := medianOf(cellDiffs)
		threshold := median * 3
		anomalous := 0
		maxDiff := 0.0
		for _, d := range cellDiffs {
			if d > threshold {
				anomalous++
			}
			if d > maxDiff {
				maxDiff = d
			}
		}
		out = append(out, GhostResult{
			Quality:        q,
			AnomalousCells: anomalous,
			TotalCells:     totalCells,
			MaxCellDiff:    roundf(maxDiff, 3),
		})
	}
	return out
}

func medianOf(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	cp := make([]float64, len(xs))
	copy(cp, xs)
	for i := 1; i < len(cp); i++ {
		for j := i; j > 0 && cp[j] < cp[j-1]; j-- {
			cp[j], cp[j-1] = cp[j-1], cp[j]
		}
	}
	return cp[len(cp)/2]
}
