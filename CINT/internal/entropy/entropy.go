package entropy

import "math"

func Shannon(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	var counts [256]int
	for _, c := range b {
		counts[c]++
	}
	n := float64(len(b))
	var h float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}

func BlockMax(b []byte, blockSize int) (maxEntropy float64, blockIndex int) {
	if blockSize < 1 {
		blockSize = 4096
	}
	maxEntropy = -1
	for i := 0; i < len(b); i += blockSize {
		end := i + blockSize
		if end > len(b) {
			end = len(b)
		}
		e := Shannon(b[i:end])
		if e > maxEntropy {
			maxEntropy = e
			blockIndex = i
		}
	}
	return
}
