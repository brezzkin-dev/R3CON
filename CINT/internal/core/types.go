package core

import (
	"time"
)

type FileEntry struct {
	Path      string    `json:"path"`
	RelPath   string    `json:"rel_path"`
	Size      int64     `json:"size"`
	Mode      uint32    `json:"mode"`
	ModTime   time.Time `json:"mod_time"`
	IsDir     bool      `json:"is_dir"`
	IsSymlink bool      `json:"is_symlink"`
	IsHidden  bool      `json:"is_hidden"`
	Readable  bool      `json:"readable"`
	Ext       string    `json:"ext"`
	Inode     uint64    `json:"inode"`
	Nlink     uint64    `json:"nlink"`
	Blocks    uint64    `json:"blocks"`
	Sparse    bool      `json:"sparse"`
}

type ChangeEvent struct {
	Kind    string    `json:"kind"`
	Path    string    `json:"path"`
	OldSize int64     `json:"old_size,omitempty"`
	NewSize int64     `json:"new_size,omitempty"`
	OldMod  time.Time `json:"old_mod,omitempty"`
	NewMod  time.Time `json:"new_mod,omitempty"`
	At      time.Time `json:"at"`
}

type DupGroup struct {
	Hash  string   `json:"hash"`
	Size  int64    `json:"size"`
	Paths []string `json:"paths"`
}

type ExtInfo struct {
	Inode  uint64
	Nlink  uint64
	Blocks uint64
}
