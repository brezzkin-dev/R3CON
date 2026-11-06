package entropy

import "testing"

func TestShannonConstant(t *testing.T) {
	// All bytes identical → entropy 0
	data := make([]byte, 100)
	for i := range data {
		data[i] = 'A'
	}
	if e := Shannon(data); e != 0 {
		t.Fatalf("constant entropy %f, want 0", e)
	}
}

func TestShannonUniform(t *testing.T) {
	// All 256 byte values evenly distributed → ~8 bits entropy
	data := make([]byte, 256)
	for i := range data {
		data[i] = byte(i)
	}
	if e := Shannon(data); e < 7.9 || e > 8.1 {
		t.Fatalf("uniform entropy %f, want ~8", e)
	}
}

func TestShannonEmpty(t *testing.T) {
	if e := Shannon(nil); e != 0 {
		t.Fatalf("empty entropy %f, want 0", e)
	}
}

func TestBlockMax(t *testing.T) {
	// First block is uniform (high entropy), second is zero-filled (low)
	data := make([]byte, 8192)
	for i := 0; i < 4096; i++ {
		data[i] = byte(i % 256)
	}
	// Second half left as zeros
	maxE, blockIdx := BlockMax(data, 4096)
	if maxE < 7.5 {
		t.Fatalf("max entropy %f, want high", maxE)
	}
	if blockIdx != 0 {
		t.Fatalf("block index %d, want 0", blockIdx)
	}
}

func TestBlockMaxEmpty(t *testing.T) {
	maxE, _ := BlockMax(nil, 4096)
	if maxE != -1 {
		t.Fatalf("empty max %f, want -1", maxE)
	}
}
