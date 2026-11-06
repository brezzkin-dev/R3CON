package index

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/brezzkin-dev/CINT/internal/core"
)

func TestSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.phfs")

	entries := []core.FileEntry{
		{RelPath: "a.txt", Size: 100, Mode: 0644, ModTime: time.Unix(1700000000, 0)},
		{RelPath: "sub/b.txt", Size: 200, Mode: 0600, ModTime: time.Unix(1700000100, 0), IsHidden: true},
		{RelPath: "sub/c", Size: 0, Mode: 0755, IsDir: true},
	}
	if err := Save(path, entries); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded) != len(entries) {
		t.Fatalf("count %d != %d", len(loaded), len(entries))
	}
	for i, want := range entries {
		got := loaded[i]
		if got.RelPath != want.RelPath {
			t.Fatalf("[%d] path %q != %q", i, got.RelPath, want.RelPath)
		}
		if got.Size != want.Size {
			t.Fatalf("[%d] size %d != %d", i, got.Size, want.Size)
		}
		if got.Mode != want.Mode {
			t.Fatalf("[%d] mode %d != %d", i, got.Mode, want.Mode)
		}
		if got.IsHidden != want.IsHidden {
			t.Fatalf("[%d] hidden %v != %v", i, got.IsHidden, want.IsHidden)
		}
		if got.IsDir != want.IsDir {
			t.Fatalf("[%d] isdir %v != %v", i, got.IsDir, want.IsDir)
		}
	}
}

func TestLoadBadMagic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.phfs")
	os.WriteFile(path, []byte("XXXX\x00\x00\x00\x00"), 0644)
	if _, err := Load(path); err == nil {
		t.Fatal("expected error on bad magic")
	}
}

func TestDiff(t *testing.T) {
	oldEntries := []core.FileEntry{
		{RelPath: "a", Size: 100, ModTime: time.Unix(1000, 0)},
		{RelPath: "b", Size: 200, ModTime: time.Unix(2000, 0)},
		{RelPath: "c", Size: 300, ModTime: time.Unix(3000, 0)},
	}
	newEntries := []core.FileEntry{
		{RelPath: "a", Size: 100, ModTime: time.Unix(1000, 0)}, // same
		{RelPath: "b", Size: 250, ModTime: time.Unix(2500, 0)}, // modified
		{RelPath: "d", Size: 400, ModTime: time.Unix(4000, 0)}, // added
	}
	changes := Diff(oldEntries, newEntries)
	kinds := map[string]int{}
	for _, c := range changes {
		kinds[c.Kind]++
	}
	if kinds["added"] != 1 {
		t.Fatalf("added: %d, want 1", kinds["added"])
	}
	if kinds["modified"] != 1 {
		t.Fatalf("modified: %d, want 1", kinds["modified"])
	}
	if kinds["deleted"] != 1 {
		t.Fatalf("deleted: %d, want 1", kinds["deleted"])
	}
}
