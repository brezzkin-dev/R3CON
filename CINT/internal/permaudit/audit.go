package permaudit

import (
	"os"

	"github.com/brezzkin-dev/CINT/internal/core"
)

type Finding struct {
	Path  string `json:"path"`
	Issue string `json:"issue"`
	Mode  string `json:"mode"`
}

func Audit(entries []core.FileEntry) []Finding {
	var out []Finding
	for _, e := range entries {
		m := os.FileMode(e.Mode)
		if e.IsDir {
			continue
		}
		if m&os.ModeSetuid != 0 {
			out = append(out, Finding{e.Path, "setuid", m.String()})
		}
		if m&os.ModeSetgid != 0 {
			out = append(out, Finding{e.Path, "setgid", m.String()})
		}
		if m&os.ModeSticky != 0 {
			out = append(out, Finding{e.Path, "sticky", m.String()})
		}
		if m.Perm()&0002 != 0 {
			out = append(out, Finding{e.Path, "world-writable", m.String()})
		}
		if e.Nlink > 1 {
			out = append(out, Finding{e.Path, "hardlink", m.String()})
		}
		if e.Sparse {
			out = append(out, Finding{e.Path, "sparse", m.String()})
		}
	}
	return out
}
