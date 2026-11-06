//go:build linux

package watch

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"
)

const watchFlags = syscall.IN_CREATE | syscall.IN_DELETE |
	syscall.IN_MODIFY | syscall.IN_MOVED_FROM | syscall.IN_MOVED_TO |
	syscall.IN_ATTRIB | syscall.IN_DELETE_SELF | syscall.IN_MOVE_SELF

func inotifyWatch(ctx context.Context, root string, cb func(Event)) error {
	fd, err := syscall.InotifyInit1(syscall.IN_CLOEXEC)
	if err != nil {
		return err
	}
	if err := addRecursive(fd, root); err != nil {
		syscall.Close(fd)
		return err
	}
	go func() {
		<-ctx.Done()
		syscall.Close(fd)
	}()
	buf := make([]byte, 64*1024)
	for {
		n, err := syscall.Read(fd, buf)
		if err != nil {
			if errors.Is(err, syscall.EBADF) {
				return nil
			}
			return err
		}
		if n <= 0 {
			continue
		}
		offset := 0
		for offset+syscall.SizeofInotifyEvent <= n {
			hdr := (*syscall.InotifyEvent)(unsafe.Pointer(&buf[offset]))
			nameLen := int(hdr.Len)
			name := ""
			if nameLen > 0 && offset+syscall.SizeofInotifyEvent+nameLen <= n {
				raw := buf[offset+syscall.SizeofInotifyEvent : offset+syscall.SizeofInotifyEvent+nameLen]
				name = trimNull(string(raw))
			}
			kind := "modified"
			if hdr.Mask&syscall.IN_CREATE != 0 {
				kind = "created"
			}
			if hdr.Mask&syscall.IN_DELETE != 0 {
				kind = "deleted"
			}
			if hdr.Mask&syscall.IN_MOVED_FROM != 0 {
				kind = "moved_from"
			}
			if hdr.Mask&syscall.IN_MOVED_TO != 0 {
				kind = "moved_to"
			}
			if hdr.Mask&syscall.IN_ISDIR != 0 && kind == "created" && name != "" {
				sub := filepath.Join(root, name)
				_ = addRecursive(fd, sub)
			}
			p := root
			if name != "" {
				p = filepath.Join(root, name)
			}
			cb(Event{Kind: kind, Path: p})
			offset += syscall.SizeofInotifyEvent + nameLen
		}
	}
}

func addRecursive(fd int, root string) error {
	return filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !info.IsDir() {
			return nil
		}
		_, werr := syscall.InotifyAddWatch(fd, p, watchFlags)
		if werr != nil {
			return nil
		}
		return nil
	})
}

func trimNull(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] == 0 {
			return s[:i]
		}
	}
	return s
}
