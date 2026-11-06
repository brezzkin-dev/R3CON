package tree

import (
	"bytes"
	"strings"
	"testing"

	"github.com/brezzkin-dev/CINT/internal/core"
)

func TestBuildTree(t *testing.T) {
	entries := []core.FileEntry{
		{RelPath: "a.txt", Size: 10},
		{RelPath: "sub/b.txt", Size: 20},
		{RelPath: "sub/deep/c.txt", Size: 30},
		{RelPath: "sub", IsDir: true},
	}
	root := Build(entries)
	if root == nil {
		t.Fatal("nil root")
	}
	if _, ok := root.Children["a.txt"]; !ok {
		t.Fatal("a.txt missing")
	}
	sub, ok := root.Children["sub"]
	if !ok {
		t.Fatal("sub missing")
	}
	if !sub.IsDir {
		t.Fatal("sub should be dir")
	}
	if _, ok := sub.Children["b.txt"]; !ok {
		t.Fatal("sub/b.txt missing")
	}
	deep, ok := sub.Children["deep"]
	if !ok {
		t.Fatal("sub/deep missing")
	}
	if _, ok := deep.Children["c.txt"]; !ok {
		t.Fatal("deep/c.txt missing")
	}
}

func TestRenderTree(t *testing.T) {
	entries := []core.FileEntry{
		{RelPath: "a.txt", Size: 10},
		{RelPath: "b.txt", Size: 20},
	}
	root := Build(entries)
	var buf bytes.Buffer
	Render(root, "", &buf)
	out := buf.String()

	if !strings.Contains(out, "a.txt") || !strings.Contains(out, "b.txt") {
		t.Fatalf("render missing files: %q", out)
	}
	if !strings.Contains(out, "(10 B)") {
		t.Fatalf("render missing size: %q", out)
	}
	if !strings.Contains(out, "(20 B)") {
		t.Fatalf("render missing size: %q", out)
	}
}

func TestRenderAlphabetical(t *testing.T) {
	entries := []core.FileEntry{
		{RelPath: "zzz", Size: 1},
		{RelPath: "aaa", Size: 1},
		{RelPath: "mmm", Size: 1},
	}
	root := Build(entries)
	var buf bytes.Buffer
	Render(root, "", &buf)
	out := buf.String()

	aIdx := strings.Index(out, "aaa")
	mIdx := strings.Index(out, "mmm")
	zIdx := strings.Index(out, "zzz")
	if aIdx < 0 || mIdx < 0 || zIdx < 0 {
		t.Fatalf("missing entries: %q", out)
	}
	if !(aIdx < mIdx && mIdx < zIdx) {
		t.Fatalf("not alphabetical: %q", out)
	}
}
