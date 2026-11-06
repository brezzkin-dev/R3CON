package dup

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/brezzkin-dev/CINT/internal/core"
	"github.com/brezzkin-dev/CINT/internal/scan"
)

func TestFindDuplicates(t *testing.T) {
	dir := t.TempDir()
	content := []byte("hello duplicate world")
	for _, name := range []string{"a.txt", "b.txt", "c.txt"} {
		if err := os.WriteFile(filepath.Join(dir, name), content, 0644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "unique.txt"), []byte("different"), 0644); err != nil {
		t.Fatal(err)
	}

	entries, err := scan.Walk(scan.Options{Root: dir})
	if err != nil {
		t.Fatal(err)
	}
	groups := Find(entries)
	if len(groups) != 1 {
		t.Fatalf("expected 1 group, got %d", len(groups))
	}
	if len(groups[0].Paths) != 3 {
		t.Fatalf("expected 3 paths in group, got %d", len(groups[0].Paths))
	}
	reclaimed := ReclaimedBytes(groups)
	if reclaimed != int64(len(content))*2 {
		t.Fatalf("expected %d reclaimed, got %d", len(content)*2, reclaimed)
	}
}

func TestNoDuplicates(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "x"), []byte("one"), 0644)
	os.WriteFile(filepath.Join(dir, "y"), []byte("two"), 0644)

	entries, _ := scan.Walk(scan.Options{Root: dir})
	groups := Find(entries)
	if len(groups) != 0 {
		t.Fatalf("expected 0 groups, got %d", len(groups))
	}
}

var _ = core.FileEntry{}
