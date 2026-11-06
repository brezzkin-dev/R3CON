// Package chunk implements FastCDC (Xia et al., USENIX ATC 2016).
package chunk

import "math/rand"

type FastCDC struct {
	table [256]uint64
	maskS uint64
	maskL uint64
	Min   int
	Avg   int
	Max   int
}

func NewFastCDC(minSize, avgSize, maxSize int, seed int64) *FastCDC {
	if minSize < 1 {
		minSize = 1
	}
	if maxSize <= minSize {
		maxSize = minSize * 2
	}
	if avgSize <= minSize || avgSize >= maxSize {
		avgSize = (minSize + maxSize) / 2
	}
	avgBits := bitsFor(avgSize)
	r := rand.New(rand.NewSource(seed))
	f := &FastCDC{
		maskS: genMask(avgBits + 2),
		maskL: genMask(avgBits - 2),
		Min:   minSize,
		Avg:   avgSize,
		Max:   maxSize,
	}
	for i := range f.table {
		f.table[i] = r.Uint64()
	}
	return f
}

func bitsFor(n int) uint {
	var b uint
	for (1 << b) < n {
		b++
	}
	return b
}

func genMask(bits uint) uint64 {
	if bits >= 64 {
		return ^uint64(0)
	}
	if bits == 0 {
		return 0
	}
	return (uint64(1) << bits) - 1
}

func (f *FastCDC) Cut(data []byte) []int {
	n := len(data)
	if n == 0 {
		return []int{0}
	}

	var cuts []int
	start := 0
	for start < n {
		minEnd := start + f.Min
		if minEnd >= n {
			cuts = append(cuts, n)
			break
		}

		var fp uint64
		pos := minEnd

		region1End := start + f.Avg
		if region1End > n {
			region1End = n
		}
		for pos < region1End {
			fp = (fp << 1) + f.table[data[pos]]
			if fp&f.maskS == 0 {
				break
			}
			pos++
		}

		region2End := start + f.Max
		if region2End > n {
			region2End = n
		}
		for pos < region2End {
			fp = (fp << 1) + f.table[data[pos]]
			if fp&f.maskL == 0 {
				break
			}
			pos++
		}

		if pos >= n {
			cuts = append(cuts, n)
			break
		}
		cuts = append(cuts, pos)
		start = pos
	}
	if len(cuts) == 0 || cuts[len(cuts)-1] != n {
		cuts = append(cuts, n)
	}
	return cuts
}

type Stats struct {
	Count, Min, Max, Sum int
}

func (s *Stats) Add(size int) {
	if s.Count == 0 || size < s.Min {
		s.Min = size
	}
	if size > s.Max {
		s.Max = size
	}
	s.Sum += size
	s.Count++
}

func (s Stats) Avg() float64 {
	if s.Count == 0 {
		return 0
	}
	return float64(s.Sum) / float64(s.Count)
}
