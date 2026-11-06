package dup

import (
	"sort"

	"github.com/brezzkin-dev/CINT/internal/core"
	"github.com/brezzkin-dev/CINT/internal/hash"
)

// Find groups same-size candidates, hashes them in parallel (xxh64), then
// returns groups with 2+ paths sharing an identical hash. Pure algorithmic
// dedupe — no content trust.
func Find(entries []core.FileEntry) []core.DupGroup {
	buckets := map[int64][]core.FileEntry{}
	for _, e := range entries {
		if e.IsDir || e.Size < 1 {
			continue
		}
		buckets[e.Size] = append(buckets[e.Size], e)
	}
	var candidates []core.FileEntry
	for _, b := range buckets {
		if len(b) >= 2 {
			candidates = append(candidates, b...)
		}
	}
	if len(candidates) == 0 {
		return nil
	}
	hashes := hash.HashParallel(simpleContext(), candidates)
	byHash := map[uint64][]core.FileEntry{}
	for _, e := range candidates {
		h, ok := hashes[e.Path]
		if !ok {
			continue
		}
		byHash[h] = append(byHash[h], e)
	}
	var groups []core.DupGroup
	for h, list := range byHash {
		if len(list) < 2 {
			continue
		}
		paths := make([]string, 0, len(list))
		for _, e := range list {
			paths = append(paths, e.Path)
		}
		groups = append(groups, core.DupGroup{
			Hash:  formatHash(h),
			Size:  list[0].Size,
			Paths: paths,
		})
	}
	sort.Slice(groups, func(i, j int) bool { return groups[i].Size > groups[j].Size })
	return groups
}

func formatHash(h uint64) string {
	const hexdigits = "0123456789abcdef"
	var buf [16]byte
	for i := 15; i >= 0; i-- {
		buf[i] = hexdigits[h&0xf]
		h >>= 4
	}
	return string(buf[:])
}

// ReclaimedBytes returns total bytes freed if every duplicate were reduced
// to a single copy per group.
func ReclaimedBytes(groups []core.DupGroup) int64 {
	var total int64
	for _, g := range groups {
		total += g.Size * int64(len(g.Paths)-1)
	}
	return total
}
