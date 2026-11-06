// Package hash provides pure-Go XXH64 with streaming support.
package hash

const (
	prime1 uint64 = 11400714785074694791
	prime2 uint64 = 14029467366897019727
	prime3 uint64 = 1609587929392839161
	prime4 uint64 = 9650029242287828579
	prime5 uint64 = 2870177450012600261
)

func rotl(x uint64, r uint) uint64 { return (x << r) | (x >> (64 - r)) }

func round(acc, input uint64) uint64 {
	acc += input * prime2
	acc = rotl(acc, 31)
	acc *= prime1
	return acc
}

func mergeRound(acc, val uint64) uint64 {
	acc ^= round(0, val)
	acc = acc*prime1 + prime4
	return acc
}

func le64(b []byte) uint64 {
	return uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24 |
		uint64(b[4])<<32 | uint64(b[5])<<40 | uint64(b[6])<<48 | uint64(b[7])<<56
}

func le32(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

func XXHash64(b []byte, seed uint64) uint64 {
	n := len(b)
	var h uint64
	if n >= 32 {
		v1 := seed + prime1 + prime2
		v2 := seed + prime2
		v3 := seed
		v4 := seed - prime1
		for i := 0; i <= n-32; i += 32 {
			v1 = round(v1, le64(b[i:]))
			v2 = round(v2, le64(b[i+8:]))
			v3 = round(v3, le64(b[i+16:]))
			v4 = round(v4, le64(b[i+24:]))
		}
		h = rotl(v1, 1) + rotl(v2, 7) + rotl(v3, 12) + rotl(v4, 18)
		h = mergeRound(h, v1)
		h = mergeRound(h, v2)
		h = mergeRound(h, v3)
		h = mergeRound(h, v4)
		b = b[n-n%32:]
	} else {
		h = seed + prime5
	}
	h += uint64(n)
	for len(b) >= 8 {
		h ^= round(0, le64(b))
		h = rotl(h, 27)*prime1 + prime4
		b = b[8:]
	}
	if len(b) >= 4 {
		h ^= uint64(le32(b)) * prime1
		h = rotl(h, 23)*prime2 + prime3
		b = b[4:]
	}
	for _, c := range b {
		h ^= uint64(c) * prime5
		h = rotl(h, 11) * prime1
	}
	h ^= h >> 33
	h *= prime2
	h ^= h >> 29
	h *= prime3
	h ^= h >> 32
	return h
}

type XXH64State struct {
	v1, v2, v3, v4 uint64
	total          uint64
	mem            [32]byte
	memSize        int
	seed           uint64
}

func NewXXH64(seed uint64) *XXH64State {
	return &XXH64State{
		v1:   seed + prime1 + prime2,
		v2:   seed + prime2,
		v3:   seed,
		v4:   seed - prime1,
		seed: seed,
	}
}

func (s *XXH64State) Write(p []byte) (int, error) {
	n := len(p)
	s.total += uint64(n)

	if s.memSize > 0 {
		need := 32 - s.memSize
		if len(p) < need {
			copy(s.mem[s.memSize:], p)
			s.memSize += len(p)
			return n, nil
		}
		copy(s.mem[s.memSize:], p[:need])
		s.consume(s.mem[:])
		p = p[need:]
		s.memSize = 0
	}

	for len(p) >= 32 {
		s.consume(p[:32])
		p = p[32:]
	}

	if len(p) > 0 {
		copy(s.mem[:], p)
		s.memSize = len(p)
	}
	return n, nil
}

func (s *XXH64State) consume(p []byte) {
	s.v1 = round(s.v1, le64(p[0:]))
	s.v2 = round(s.v2, le64(p[8:]))
	s.v3 = round(s.v3, le64(p[16:]))
	s.v4 = round(s.v4, le64(p[24:]))
}

func (s *XXH64State) Sum64() uint64 {
	var h uint64
	if s.total >= 32 {
		h = rotl(s.v1, 1) + rotl(s.v2, 7) + rotl(s.v3, 12) + rotl(s.v4, 18)
		h = mergeRound(h, s.v1)
		h = mergeRound(h, s.v2)
		h = mergeRound(h, s.v3)
		h = mergeRound(h, s.v4)
	} else {
		h = s.seed + prime5
	}
	h += s.total

	b := s.mem[:s.memSize]
	for len(b) >= 8 {
		h ^= round(0, le64(b))
		h = rotl(h, 27)*prime1 + prime4
		b = b[8:]
	}
	if len(b) >= 4 {
		h ^= uint64(le32(b)) * prime1
		h = rotl(h, 23)*prime2 + prime3
		b = b[4:]
	}
	for _, c := range b {
		h ^= uint64(c) * prime5
		h = rotl(h, 11) * prime1
	}
	h ^= h >> 33
	h *= prime2
	h ^= h >> 29
	h *= prime3
	h ^= h >> 32
	return h
}

func (s *XXH64State) Reset() {
	*s = *NewXXH64(s.seed)
}
