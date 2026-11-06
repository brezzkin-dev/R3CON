package hash

import "testing"

// Reference vectors from the xxHash specification (xxh64 with seed=0).
// If this test fails, the algorithm is wrong.
func TestXXH64Vectors(t *testing.T) {
	cases := []struct {
		in   string
		want uint64
	}{
		{"", 0xef46db3751d8e999},
		{"a", 0xd24ec4f1a98c6e5b},
		{"abc", 0x44bc2cf5ad770999},
		{"1234567890", 0xa9d4d4132eff23b6},
		{"hi", 0xea8842e9ea2638fa},
		{"xxhash", 0x32dd38952c4bc720},
	}
	for _, c := range cases {
		got := XXHash64([]byte(c.in), 0)
		if got != c.want {
			t.Fatalf("XXH64(%q) = %016x, want %016x", c.in, got, c.want)
		}
	}
}

func TestStreamingMatchesOneShot(t *testing.T) {
	data := make([]byte, 100_000)
	for i := range data {
		data[i] = byte(i * 37)
	}
	want := XXHash64(data, 0)

	for _, chunkSize := range []int{1, 7, 31, 32, 33, 64, 1000, 8192} {
		st := NewXXH64(0)
		for i := 0; i < len(data); i += chunkSize {
			end := i + chunkSize
			if end > len(data) {
				end = len(data)
			}
			if _, err := st.Write(data[i:end]); err != nil {
				t.Fatalf("write: %v", err)
			}
		}
		if got := st.Sum64(); got != want {
			t.Fatalf("chunk=%d: streaming %016x != one-shot %016x", chunkSize, got, want)
		}
	}
}

func TestStreamingReset(t *testing.T) {
	st := NewXXH64(0)
	st.Write([]byte("hello"))
	h1 := st.Sum64()

	st.Reset()
	st.Write([]byte("hello"))
	h2 := st.Sum64()

	if h1 != h2 {
		t.Fatalf("reset didn't restore: %016x != %016x", h1, h2)
	}
}

func BenchmarkXXH64OneShot(b *testing.B) {
	data := make([]byte, 1<<20)
	b.SetBytes(int64(len(data)))
	for i := 0; i < b.N; i++ {
		_ = XXHash64(data, 0)
	}
}

func BenchmarkXXH64_Streaming(b *testing.B) {
	data := make([]byte, 1<<20)
	b.SetBytes(int64(len(data)))
	buf := make([]byte, 64*1024)

	for i := 0; i < b.N; i++ {
		st := NewXXH64(0)
		for off := 0; off < len(data); off += len(buf) {
			end := off + len(buf)
			if end > len(data) {
				end = len(data)
			}
			st.Write(data[off:end])
		}
		_ = st.Sum64()
	}
}
