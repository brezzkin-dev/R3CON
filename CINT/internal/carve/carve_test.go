package carve

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestCarveEmpty(t *testing.T) {
	dir := t.TempDir()
	out, err := Carve(nil, dir)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("expected 0, got %d", len(out))
	}
}

func TestCarveBounds(t *testing.T) {
	// Truncated signatures must not panic.
	junk := []byte("\xff\xd8\xff" + "garbage without end marker")
	out, err := Carve(junk, t.TempDir())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("expected 0, got %d", len(out))
	}
}

func TestCarveJPEG(t *testing.T) {
	data := []byte("prefix \xff\xd8\xfffakebody\xff\xd9 suffix")
	dir := t.TempDir()
	out, err := Carve(data, dir)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("expected 1, got %d", len(out))
	}
	if out[0].Type != "JPEG" {
		t.Fatalf("type %s", out[0].Type)
	}
	got, _ := os.ReadFile(out[0].Path)
	if !bytes.Equal(got, data[out[0].Offset:out[0].Offset+out[0].Size]) {
		t.Fatalf("content mismatch")
	}
}

func TestCarveTwoJPEGs(t *testing.T) {
	data := []byte("\xff\xd8\xffAAA\xff\xd9__\xff\xd8\xffBBB\xff\xd9")
	out, err := Carve(data, t.TempDir())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("expected 2, got %d", len(out))
	}
	if out[0].Offset >= out[1].Offset {
		t.Fatalf("not monotonic: %d >= %d", out[0].Offset, out[1].Offset)
	}
}

func TestCarveFileReadError(t *testing.T) {
	_, err := CarveFile(filepath.Join(t.TempDir(), "missing"), t.TempDir())
	if err == nil {
		t.Fatalf("expected error")
	}
}
