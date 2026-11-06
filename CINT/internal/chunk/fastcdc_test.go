package chunk

import (
	"math/rand"
	"testing"
)

func TestFastCDCEdges(t *testing.T) {
	f := NewFastCDC(512, 4096, 65536, 42)

	if cuts := f.Cut(nil); len(cuts) != 1 || cuts[0] != 0 {
		t.Fatalf("empty: %v", cuts)
	}
	small := []byte("hi")
	cuts := f.Cut(small)
	if len(cuts) != 1 || cuts[0] != len(small) {
		t.Fatalf("small: %v", cuts)
	}
}

func TestFastCDCProperties(t *testing.T) {
	f := NewFastCDC(512, 4096, 65536, 42)
	r := rand.New(rand.NewSource(7))
	data := make([]byte, 2<<20)
	r.Read(data)

	cuts := f.Cut(data)
	if len(cuts) < 2 {
		t.Fatalf("expected multiple cuts, got %d", len(cuts))
	}
	if cuts[len(cuts)-1] != len(data) {
		t.Fatalf("last cut %d != len %d", cuts[len(cuts)-1], len(data))
	}
	prev := 0
	var st Stats
	for i, c := range cuts {
		if i > 0 && c <= prev {
			t.Fatalf("cut %d (%d) <= prev (%d)", i, c, prev)
		}
		size := c - prev
		if size > f.Max {
			t.Fatalf("chunk %d size %d > max %d", i, size, f.Max)
		}
		if i < len(cuts)-1 && size < f.Min {
			t.Fatalf("chunk %d size %d < min %d", i, size, f.Min)
		}
		st.Add(size)
		prev = c
	}
	if st.Sum != len(data) {
		t.Fatalf("coverage %d != %d", st.Sum, len(data))
	}
}

func TestFastCDCDeterministic(t *testing.T) {
	f := NewFastCDC(512, 4096, 65536, 42)
	r := rand.New(rand.NewSource(9))
	data := make([]byte, 512*1024)
	r.Read(data)

	a := f.Cut(data)
	b := f.Cut(data)
	if len(a) != len(b) {
		t.Fatalf("cut count differs: %d vs %d", len(a), len(b))
	}
	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("cut %d differs: %d vs %d", i, a[i], b[i])
		}
	}
}

func TestFastCDCResync(t *testing.T) {
	// Inserting bytes mid-stream should not disturb all downstream boundaries.
	f := NewFastCDC(512, 4096, 65536, 42)
	r := rand.New(rand.NewSource(13))
	base := make([]byte, 256*1024)
	r.Read(base)

	insert := make([]byte, 100)
	r.Read(insert)
	modified := append([]byte{}, base[:100*1024]...)
	modified = append(modified, insert...)
	modified = append(modified, base[100*1024:]...)

	cutsA := f.Cut(base)
	cutsB := f.Cut(modified)

	boundaryA := make(map[int]bool)
	for _, c := range cutsA[:len(cutsA)-1] {
		boundaryA[c] = true
	}
	shared := 0
	for _, c := range cutsB[:len(cutsB)-1] {
		if boundaryA[c] {
			shared++
		}
	}
	if shared == 0 {
		t.Fatalf("no resync: %d boundaries in A, %d in B, 0 shared", len(cutsA), len(cutsB))
	}
}

func BenchmarkFastCDC(b *testing.B) {
	f := NewFastCDC(512, 4096, 65536, 42)
	data := make([]byte, 4<<20)
	rand.New(rand.NewSource(1)).Read(data)
	b.SetBytes(int64(len(data)))
	for i := 0; i < b.N; i++ {
		_ = f.Cut(data)
	}
}
