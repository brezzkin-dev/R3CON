package cryptan

import (
	"crypto/aes"
	"encoding/hex"
	"fmt"

	core "github.com/brezzkin-dev/CINT/internal/cyber/core"
)

func DetectECB(ct []byte) *core.Result {
	r := core.NewResult("cryptan-ecb", "")
	blockSize := aes.BlockSize
	if len(ct) < blockSize*2 {
		r.Add(core.Finding{Tool: "cryptan", Severity: core.SevHigh,
			Title: "ciphertext too short"})
		r.Finish()
		return r
	}

	blocks := map[string]int{}
	for i := 0; i+blockSize <= len(ct); i += blockSize {
		key := hex.EncodeToString(ct[i : i+blockSize])
		blocks[key]++
	}
	dups := 0
	for _, n := range blocks {
		if n > 1 {
			dups += n - 1
		}
	}
	r.AddExtra("block_count", len(ct)/blockSize)
	r.AddExtra("duplicate_blocks", dups)

	if dups > 0 {
		r.Add(core.Finding{
			Tool: "cryptan", Severity: core.SevHigh,
			Title:    "ECB mode suspected",
			Detail:   fmt.Sprintf("%d duplicate 16-byte blocks", dups),
			Evidence: map[string]any{"duplicates": dups},
		})
	} else {
		r.Add(core.Finding{Tool: "cryptan", Severity: core.SevInfo,
			Title: "no duplicate blocks — likely CBC/CTR"})
	}
	r.Finish()
	return r
}
