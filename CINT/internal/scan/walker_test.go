package scan

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

func buildTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	files := map[string]string{
		"a.txt":       "hello",
		"b.txt":       "world",
		"sub/c.txt":   "nested",
		"sub/d.txt":   "deeper",
		"sub/in/e":    "three",
		".hidden":     "x",
		"sub/.dotf":   "y",
	}
	for name, content := range files {
		p := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestWalkFindsAllFiles(t *testing.T) {
	root := buildTree(t)
	entries, err := Walk(Options{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	var files []string
	for _, e := range entries {
		if !e.IsDir {
			files = append(files, e.RelPath)
		}
	}
	sort.Strings(files)
	want := []string{".hidden", "a.txt", "b.txt", "sub/.dotf", "sub/c.txt", "sub/d.txt", "sub/in/e"}
	if len(files) != len(want) {
		t.Fatalf("file count: got %d want %d\nfiles=%v", len(files), len(want), files)
	}
}

func TestWalkMaxDepth(t *testing.T) {
	root := buildTree(t)
	entries, err := WalkContext(context.Background(), Options{Root: root, MaxDepth: 1})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		depth := 0
		for _, c := range e.RelPath {
			if c == filepath.Separator {
				depth++
			}
		}
		if depth > 0 {
			t.Fatalf("depth exceeded: %s", e.RelPath)
		}
	}
}

func TestWalkMinSize(t *testing.T) {
	root := buildTree(t)
	entries, err := Walk(Options{Root: root, MinSize: 6})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.IsDir {
			continue
		}
		if e.Size < 6 {
			t.Fatalf("file under minsize: %s (%d)", e.RelPath, e.Size)
		}
	}
}

func TestWalkHidden(t *testing.T) {
	root := buildTree(t)
	entries, err := Walk(Options{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	hidden := 0
	for _, e := range entries {
		if e.IsHidden && !e.IsDir {
			hidden++
		}
	}
	if hidden < 2 {
		t.Fatalf("expected at least 2 hidden files, got %d", hidden)
	}
}

func TestWalkParallelConsistent(t *testing.T) {
	root := buildTree(t)
	serial, err := WalkContext(context.Background(), Options{Root: root, Workers: 1})
	if err != nil {
		t.Fatal(err)
	}
	parallel, err := WalkContext(context.Background(), Options{Root: root, Workers: 8})
	if err != nil {
		t.Fatal(err)
	}
	if len(serial) != len(parallel) {
		t.Fatalf("serial %d != parallel %d", len(serial), len(parallel))
	}
}

func TestWalkCancellation(t *testing.T) {
	root := buildTree(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// Should return quickly without hanging.
	entries, _ := WalkContext(ctx, Options{Root: root})
	_ = entries
}
