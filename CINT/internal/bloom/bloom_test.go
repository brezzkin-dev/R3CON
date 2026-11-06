package bloom

import (
	"math/rand"
	"testing"
)

func TestBloomEmpty(t *testing.T) {
	f := New(1000, 0.01)
	for i := 0; i < 100; i++ {
		if f.Contains(uint64(i), uint64(i*7+1)) {
			t.Fatalf("empty filter returned true for %d", i)
		}
	}
}

func TestBloomNoFalseNegatives(t *testing.T) {
	f := New(1000, 0.01)
	r := rand.New(rand.NewSource(1))
	added := make([][2]uint64, 0, 1000)
	for i := 0; i < 1000; i++ {
		h1 := r.Uint64()
		h2 := r.Uint64()
		f.Add(h1, h2)
		added = append(added, [2]uint64{h1, h2})
	}
	for _, p := range added {
		if !f.Contains(p[0], p[1]) {
			t.Fatalf("false negative for %v", p)
		}
	}
}

func TestBloomFPRate(t *testing.T) {
	n := uint64(10000)
	f := New(n, 0.01)
	r := rand.New(rand.NewSource(2))
	for i := uint64(0); i < n; i++ {
		f.Add(r.Uint64(), r.Uint64())
	}
	// Query 10000 random values; expect <= ~2% false positives.
	fp := 0
	for i := 0; i < 10000; i++ {
		if f.Contains(r.Uint64(), r.Uint64()) {
			fp++
		}
	}
	if fp > 200 {
		t.Fatalf("FP rate too high: %d/10000", fp)
	}
}

func TestBloomSizing(t *testing.T) {
	f := New(1000, 0.01)
	if f.K() < 1 {
		t.Fatalf("k = %d", f.K())
	}
	if f.Size() == 0 {
		t.Fatalf("size = 0")
	}
}
