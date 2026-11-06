package hidden

import (
	"strings"

	"github.com/brezzkin-dev/CINT/internal/core"
)

type Report struct {
	DotFiles   []core.FileEntry `json:"dot_files"`
	Symlinks   []core.FileEntry `json:"symlinks"`
	Unreadable []core.FileEntry `json:"unreadable"`
	DeepPaths  []core.FileEntry `json:"deep_paths"`
	ZeroByte   []core.FileEntry `json:"zero_byte"`
	ExecFiles  []core.FileEntry `json:"exec_files"`
	Hardlinks  []core.FileEntry `json:"hardlinks"`
	Sparse     []core.FileEntry `json:"sparse"`
}

func Detect(entries []core.FileEntry) Report {
	var r Report
	for _, e := range entries {
		if e.IsHidden {
			r.DotFiles = append(r.DotFiles, e)
		}
		if e.IsSymlink {
			r.Symlinks = append(r.Symlinks, e)
		}
		if !e.IsDir && !e.Readable {
			r.Unreadable = append(r.Unreadable, e)
		}
		if strings.Count(e.RelPath, string('/')) >= 8 {
			r.DeepPaths = append(r.DeepPaths, e)
		}
		if !e.IsDir && e.Size == 0 {
			r.ZeroByte = append(r.ZeroByte, e)
		}
		if !e.IsDir && e.Mode&0111 != 0 {
			r.ExecFiles = append(r.ExecFiles, e)
		}
		if e.Nlink > 1 {
			r.Hardlinks = append(r.Hardlinks, e)
		}
		if e.Sparse {
			r.Sparse = append(r.Sparse, e)
		}
	}
	return r
}
