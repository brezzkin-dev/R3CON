package t07_phototrace

import (
	"hash/fnv"
	"image"
)

type Region struct {
	X1    int     `json:"x1"`
	Y1    int     `json:"y1"`
	X2    int     `json:"x2"`
	Y2    int     `json:"y2"`
	Score float64 `json:"score"`
	Hash  string  `json:"hash"`
}

type CopyMoveResult struct {
	BlockSize  int      `json:"block_size"`
	Duplicates int      `json:"duplicates"`
	Truncated  bool     `json:"truncated"`
	Regions    []Region `json:"regions"`
}

const (
	cmMaxPixels  = 40_000_000
	cmMaxBlocks  = 250_000
	cmMinShift   = 32
	cmMaxRegions = 40
)

// DetectCopyMove hashes 16x16 blocks and finds duplicate hashes at
// distant positions. Bounds: max 40 MP pixels, max 250k blocks, per-hash
// pair cap 20, region cap 40. Oversize images return {Truncated: true}
// without scanning.
func DetectCopyMove(img image.Image) *CopyMoveResult {
	b := img.Bounds()
	w, h := b.Dx(), b.Dy()
	if int64(w)*int64(h) > cmMaxPixels {
		return &CopyMoveResult{Truncated: true}
	}

	const bs = 16
	type block struct {
		x, y int
		hash uint64
	}
	var blocks []block
	for y := b.Min.Y; y+bs <= b.Max.Y; y += bs {
		for x := b.Min.X; x+bs <= b.Max.X; x += bs {
			if len(blocks) >= cmMaxBlocks {
				goto scan
			}
			hh := fnv.New64a()
			for yy := 0; yy < bs; yy += 2 {
				for xx := 0; xx < bs; xx += 2 {
					r, g, bb, _ := img.At(x+xx, y+yy).RGBA()
					hh.Write([]byte{byte(r >> 8), byte(g >> 8), byte(bb >> 8)})
				}
			}
			blocks = append(blocks, block{x: x, y: y, hash: hh.Sum64()})
		}
	}

scan:
	byHash := map[uint64][]block{}
	for _, b2 := range blocks {
		byHash[b2.hash] = append(byHash[b2.hash], b2)
	}

	var regions []Region
	budget := cmMaxRegions * 4
	for hh, list := range byHash {
		if len(list) < 2 {
			continue
		}
		capped := list
		if len(capped) > 20 {
			capped = capped[:20]
		}
		for i := 0; i < len(capped); i++ {
			for j := i + 1; j < len(capped); j++ {
				dx := absInt(capped[i].x - capped[j].x)
				dy := absInt(capped[i].y - capped[j].y)
				if dx+dy < cmMinShift {
					continue
				}
				regions = append(regions, Region{
					X1: capped[i].x, Y1: capped[i].y,
					X2: capped[j].x, Y2: capped[j].y,
					Score: 1.0,
					Hash:  hashHex(hh),
				})
				if len(regions) >= budget {
					goto emit
				}
			}
		}
	}

emit:
	sortRegionsByConfidence(regions)
	truncated := false
	if len(regions) > cmMaxRegions {
		regions = regions[:cmMaxRegions]
		truncated = true
	}
	return &CopyMoveResult{
		BlockSize:  bs,
		Duplicates: len(regions),
		Truncated:  truncated,
		Regions:    regions,
	}
}

func absInt(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

func hashHex(v uint64) string {
	const hex = "0123456789abcdef"
	var b [16]byte
	for i := 15; i >= 0; i-- {
		b[i] = hex[v&0xf]
		v >>= 4
	}
	return string(b[:])
}
