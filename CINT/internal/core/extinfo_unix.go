//go:build linux || darwin

package core

import (
	"os"
	"syscall"
)

func ExtInfoOf(info os.FileInfo) ExtInfo {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return ExtInfo{}
	}
	return ExtInfo{
		Inode:  uint64(st.Ino),
		Nlink:  uint64(st.Nlink),
		Blocks: uint64(st.Blocks),
	}
}
