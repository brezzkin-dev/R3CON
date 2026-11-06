package index

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"time"

	"github.com/brezzkin-dev/CINT/internal/core"
)

const magic = "PHFS"
const version uint16 = 2

func Save(path string, entries []core.FileEntry) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	defer w.Flush()
	if _, err := w.WriteString(magic); err != nil {
		return err
	}
	if err := binary.Write(w, binary.LittleEndian, version); err != nil {
		return err
	}
	if err := binary.Write(w, binary.LittleEndian, uint32(len(entries))); err != nil {
		return err
	}
	for _, e := range entries {
		if err := writeEntry(w, e); err != nil {
			return err
		}
	}
	return nil
}

func writeEntry(w *bufio.Writer, e core.FileEntry) error {
	if err := binary.Write(w, binary.LittleEndian, uint32(len(e.RelPath))); err != nil {
		return err
	}
	if _, err := w.WriteString(e.RelPath); err != nil {
		return err
	}
	binary.Write(w, binary.LittleEndian, e.Size)
	binary.Write(w, binary.LittleEndian, e.Mode)
	binary.Write(w, binary.LittleEndian, e.ModTime.UnixNano())
	var flags uint8
	if e.IsDir {
		flags |= 1
	}
	if e.IsHidden {
		flags |= 2
	}
	if e.IsSymlink {
		flags |= 4
	}
	binary.Write(w, binary.LittleEndian, flags)
	return nil
}

func Load(path string) ([]core.FileEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	r := bufio.NewReader(f)
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, err
	}
	if string(hdr) != magic {
		return nil, errors.New("not a phantomfs index")
	}
	var ver uint16
	if err := binary.Read(r, binary.LittleEndian, &ver); err != nil {
		return nil, err
	}
	if ver != version {
		return nil, errors.New("unsupported index version")
	}
	var count uint32
	if err := binary.Read(r, binary.LittleEndian, &count); err != nil {
		return nil, err
	}
	entries := make([]core.FileEntry, 0, count)
	for i := uint32(0); i < count; i++ {
		var plen uint32
		if err := binary.Read(r, binary.LittleEndian, &plen); err != nil {
			return nil, err
		}
		pbuf := make([]byte, plen)
		if _, err := io.ReadFull(r, pbuf); err != nil {
			return nil, err
		}
		var size int64
		var mode uint32
		var mt int64
		var flags uint8
		if err := binary.Read(r, binary.LittleEndian, &size); err != nil {
			return nil, err
		}
		if err := binary.Read(r, binary.LittleEndian, &mode); err != nil {
			return nil, err
		}
		if err := binary.Read(r, binary.LittleEndian, &mt); err != nil {
			return nil, err
		}
		if err := binary.Read(r, binary.LittleEndian, &flags); err != nil {
			return nil, err
		}
		entries = append(entries, core.FileEntry{
			RelPath:   string(pbuf),
			Size:      size,
			Mode:      mode,
			ModTime:   time.Unix(0, mt),
			IsDir:     flags&1 != 0,
			IsHidden:  flags&2 != 0,
			IsSymlink: flags&4 != 0,
		})
	}
	return entries, nil
}

type Change struct {
	Kind    string `json:"kind"`
	Path    string `json:"path"`
	OldSize int64  `json:"old_size,omitempty"`
	NewSize int64  `json:"new_size,omitempty"`
}

func Diff(oldEntries, newEntries []core.FileEntry) []Change {
	oldMap := make(map[string]core.FileEntry, len(oldEntries))
	for _, e := range oldEntries {
		oldMap[e.RelPath] = e
	}
	var changes []Change
	for _, e := range newEntries {
		old, ok := oldMap[e.RelPath]
		if !ok {
			changes = append(changes, Change{Kind: "added", Path: e.RelPath, NewSize: e.Size})
		} else if old.Size != e.Size || !old.ModTime.Equal(e.ModTime) {
			changes = append(changes, Change{
				Kind: "modified", Path: e.RelPath,
				OldSize: old.Size, NewSize: e.Size,
			})
		}
		delete(oldMap, e.RelPath)
	}
	for p, e := range oldMap {
		changes = append(changes, Change{Kind: "deleted", Path: p, OldSize: e.Size})
	}
	return changes
}
