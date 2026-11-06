package t07_phototrace

import (
	"image"
	"math"
)

type ChromaResult struct {
	RedVsGreenEdge     float64 `json:"red_vs_green_edge"`
	BlueVsGreenEdge    float64 `json:"blue_vs_green_edge"`
	ChannelDiscrepancy float64 `json:"channel_discrepancy"`
}

func ChromaticAberration(img image.Image) *ChromaResult {
	b := img.Bounds()
	w, h := b.Dx(), b.Dy()
	if w < 8 || h < 8 {
		return nil
	}

	R := make([][]float64, h)
	G := make([][]float64, h)
	B := make([][]float64, h)
	for y := 0; y < h; y++ {
		R[y] = make([]float64, w)
		G[y] = make([]float64, w)
		B[y] = make([]float64, w)
		for x := 0; x < w; x++ {
			r, g, bb, _ := img.At(b.Min.X+x, b.Min.Y+y).RGBA()
			R[y][x] = float64(r >> 8)
			G[y][x] = float64(g >> 8)
			B[y][x] = float64(bb >> 8)
		}
	}

	edge := func(ch [][]float64) float64 {
		var sum float64
		for y := 1; y < h-1; y++ {
			for x := 1; x < w-1; x++ {
				gx := -ch[y-1][x-1] - 2*ch[y][x-1] - ch[y+1][x-1] +
					ch[y-1][x+1] + 2*ch[y][x+1] + ch[y+1][x+1]
				gy := -ch[y-1][x-1] - 2*ch[y-1][x] - ch[y-1][x+1] +
					ch[y+1][x-1] + 2*ch[y+1][x] + ch[y+1][x+1]
				sum += math.Sqrt(gx*gx + gy*gy)
			}
		}
		return sum
	}

	rEdge := edge(R)
	gEdge := edge(G)
	bEdge := edge(B)

	rg := 0.0
	bg := 0.0
	if gEdge > 0.001 {
		rg = math.Abs(rEdge-gEdge) / gEdge
		bg = math.Abs(bEdge-gEdge) / gEdge
	}
	discrepancy := (rg + bg) / 2
	return &ChromaResult{
		RedVsGreenEdge:     roundf(rg, 4),
		BlueVsGreenEdge:    roundf(bg, 4),
		ChannelDiscrepancy: roundf(discrepancy, 4),
	}
}
