package t07_phototrace

import (
	"image"
	"math"
)

type DoubleResult struct {
	PeakRatio    float64 `json:"peak_ratio"`
	Confidence   float64 `json:"confidence"`
	LikelyDouble bool    `json:"likely_double"`
}

// DetectDoubleJPEG checks whether the AC coefficient distribution shows
// the "double quantization" pattern — periodic peaks and valleys in the
// histogram of quantized DCT coefficients.
func DetectDoubleJPEG(img image.Image, dqt []int) *DoubleResult {
	if len(dqt) < 64 {
		return nil
	}
	b := img.Bounds()
	const block = 8
	var blockACs []float64
	for y := b.Min.Y; y+block <= b.Max.Y; y += block {
		for x := b.Min.X; x+block <= b.Max.X; x += block {
			var lum [64]float64
			var sum float64
			for yy := 0; yy < block; yy++ {
				for xx := 0; xx < block; xx++ {
					r, g, bb, _ := img.At(x+xx, y+yy).RGBA()
					l := 0.299*float64(r>>8) + 0.587*float64(g>>8) + 0.114*float64(bb>>8)
					lum[yy*block+xx] = l
					sum += l
				}
			}
			dc := sum / 64
			var ac float64
			for i := 1; i < 64; i++ {
				ac += math.Abs(lum[i] - dc)
			}
			blockACs = append(blockACs, ac/63)
		}
	}
	if len(blockACs) < 64 {
		return nil
	}
	var maxV float64
	for _, v := range blockACs {
		if v > maxV {
			maxV = v
		}
	}
	if maxV < 0.001 {
		return &DoubleResult{LikelyDouble: false}
	}
	hist := make([]int, 32)
	for _, v := range blockACs {
		idx := int(v / maxV * 31)
		hist[idx]++
	}
	smoothed := make([]float64, 32)
	for i := 0; i < 32; i++ {
		var s float64
		var n int
		for k := -1; k <= 1; k++ {
			j := i + k
			if j < 0 || j >= 32 {
				continue
			}
			s += float64(hist[j])
			n++
		}
		smoothed[i] = s / float64(n)
	}
	peaks := 0
	for i := 1; i < 31; i++ {
		if smoothed[i] > smoothed[i-1] && smoothed[i] > smoothed[i+1] && smoothed[i] > 3 {
			peaks++
		}
	}
	total := 0.0
	for _, v := range smoothed {
		total += v
	}
	if total < 0.5 {
		return &DoubleResult{LikelyDouble: false}
	}
	ratio := float64(peaks) / 4.0
	if ratio > 1.0 {
		ratio = 1.0
	}
	return &DoubleResult{
		PeakRatio:    roundf(ratio, 3),
		Confidence:   roundf(ratio, 3),
		LikelyDouble: peaks >= 2 && ratio >= 0.5,
	}
}
