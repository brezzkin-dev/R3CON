package t07_phototrace

import (
	"bytes"
	"image"
	"image/color"
	"image/jpeg"
	"math"
	"os"
)

type ELAResult struct {
	MeanDiff        float64 `json:"mean_diff"`
	MaxDiff         int     `json:"max_diff"`
	AnomalousPixels int     `json:"anomalous_pixels"`
	AnomalousRatio  float64 `json:"anomalous_ratio"`
	Threshold       float64 `json:"threshold"`
	Histogram       []int   `json:"histogram_32buckets"`
}

func ELA(path string, orig image.Image) (*ELAResult, error) {
	buf := &bytes.Buffer{}
	if err := jpeg.Encode(buf, orig, &jpeg.Options{Quality: 90}); err != nil {
		return nil, err
	}
	recompressed, err := jpeg.Decode(buf)
	if err != nil {
		return nil, err
	}

	b := orig.Bounds()
	total := b.Dx() * b.Dy()
	if total == 0 {
		return nil, nil
	}
	var sum float64
	var maxDiff int
	const threshold = 25.0
	anomalous := 0
	hist := make([]int, 32)

	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			r1, g1, b1, _ := orig.At(x, y).RGBA()
			r2, g2, b2, _ := recompressed.At(x, y).RGBA()
			dr := math.Abs(float64(r1>>8) - float64(r2>>8))
			dg := math.Abs(float64(g1>>8) - float64(g2>>8))
			db := math.Abs(float64(b1>>8) - float64(b2>>8))
			d := (dr + dg + db) / 3
			sum += d
			if int(d) > maxDiff {
				maxDiff = int(d)
			}
			if d > threshold {
				anomalous++
			}
			bucket := int(d / 8)
			if bucket >= 32 {
				bucket = 31
			}
			hist[bucket]++
		}
	}

	return &ELAResult{
		MeanDiff:        sum / float64(total),
		MaxDiff:         maxDiff,
		AnomalousPixels: anomalous,
		AnomalousRatio:  float64(anomalous) / float64(total),
		Threshold:       threshold,
		Histogram:       hist,
	}, nil
}

func SaveELAImage(inPath, outPath string) error {
	f, err := os.Open(inPath)
	if err != nil {
		return err
	}
	orig, err := jpeg.Decode(f)
	f.Close()
	if err != nil {
		return err
	}
	buf := &bytes.Buffer{}
	if err := jpeg.Encode(buf, orig, &jpeg.Options{Quality: 90}); err != nil {
		return err
	}
	recompressed, err := jpeg.Decode(buf)
	if err != nil {
		return err
	}

	b := orig.Bounds()
	outImg := image.NewGray(b)
	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			r1, g1, b1, _ := orig.At(x, y).RGBA()
			r2, g2, b2, _ := recompressed.At(x, y).RGBA()
			d := (math.Abs(float64(r1>>8)-float64(r2>>8)) +
				math.Abs(float64(g1>>8)-float64(g2>>8)) +
				math.Abs(float64(b1>>8)-float64(b2>>8))) / 3
			amp := d * 15
			if amp > 255 {
				amp = 255
			}
			outImg.Set(x, y, color.Gray{Y: uint8(amp)})
		}
	}

	out, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer out.Close()
	return jpeg.Encode(out, outImg, &jpeg.Options{Quality: 92})
}
