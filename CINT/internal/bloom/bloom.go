package bloom

import "math"

type Filter struct {
	bits []uint64
	k    int
	m    uint64
}

func New(expected uint64, fpRate float64) *Filter {
	if expected < 1 {
		expected = 1
	}
	if fpRate <= 0 || fpRate >= 1 {
		fpRate = 0.01
	}
	m := uint64(math.Ceil(-float64(expected) * math.Log(fpRate) / (math.Ln2 * math.Ln2)))
	k := int(math.Round(float64(m) / float64(expected) * math.Ln2))
	if k < 1 {
		k = 1
	}
	return &Filter{
		bits: make([]uint64, (m+63)/64),
		k:    k,
		m:    m,
	}
}

func (f *Filter) Add(h1, h2 uint64) {
	for i := 0; i < f.k; i++ {
		pos := (h1 + uint64(i)*h2) % f.m
		f.bits[pos/64] |= 1 << (pos % 64)
	}
}

func (f *Filter) Contains(h1, h2 uint64) bool {
	for i := 0; i < f.k; i++ {
		pos := (h1 + uint64(i)*h2) % f.m
		if f.bits[pos/64]&(1<<(pos%64)) == 0 {
			return false
		}
	}
	return true
}

func (f *Filter) Size() uint64 { return f.m }
func (f *Filter) K() int       { return f.k }
