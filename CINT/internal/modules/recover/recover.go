package recover

import (
	"os"
	"path/filepath"

	"github.com/brezzkin-dev/CINT/internal/core"
	"github.com/brezzkin-dev/CINT/internal/scan"
)

// Reconstruct re-creates missing parent directories for every path in the
// tree. This does not recover file content — for that see carve.
func Reconstruct(root string) (int, error) {
	entries, err := scan.Walk(scan.Options{Root: root})
	if err != nil {
		return 0, err
	}
	seen := map[string]bool{}
	for _, e := range entries {
		dir := filepath.Dir(e.Path)
		if !seen[dir] {
			seen[dir] = true
			if err := os.MkdirAll(dir, 0755); err != nil {
				core.Warnf("mkdir %s: %v", dir, err)
			}
		}
	}
	return len(seen), nil
}
