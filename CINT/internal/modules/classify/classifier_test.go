package classify

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/brezzkin-dev/CINT/internal/core"
)

func TestClassifyByExtension(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "test.tmp")
	os.WriteFile(p, []byte("x"), 0644)

	entries := []core.FileEntry{{Path: p, Ext: ".tmp", Size: 1}}
	results := Classify(entries, nil)
	if len(results) != 1 {
		t.Fatalf("count %d", len(results))
	}
	if results[0].Category != "temp" {
		t.Fatalf("category %q, want temp", results[0].Category)
	}
}

func TestClassifyEmptyFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "empty")
	os.WriteFile(p, nil, 0644)

	entries := []core.FileEntry{{Path: p, Size: 0}}
	results := Classify(entries, nil)
	if results[0].Category != "empty" {
		t.Fatalf("category %q, want empty", results[0].Category)
	}
}

func TestClassifyMagicBeatsExt(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "notreally.exe")
	// Write an ELF header into a .exe file
	data := append([]byte("\x7fELF"), make([]byte, 100)...)
	os.WriteFile(p, data, 0644)

	entries := []core.FileEntry{{Path: p, Ext: ".exe", Size: int64(len(data))}}
	results := Classify(entries, nil)
	if len(results) != 1 {
		t.Fatalf("count %d", len(results))
	}
	// Magic wins, so category should be magic:ELF-related not "executable"
	if results[0].Category == "executable" {
		t.Fatalf("expected magic to beat ext, got %q", results[0].Category)
	}
}

func TestClassifyCustomRules(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "file.xyz")
	os.WriteFile(p, []byte("data"), 0644)

	rules := []Rule{
		{Name: "custom", Kind: "ext", Pattern: ".xyz", MinSize: 0, MaxSize: -1, Severity: "high", Desc: "custom rule"},
	}
	entries := []core.FileEntry{{Path: p, Ext: ".xyz", Size: 4}}
	results := Classify(entries, rules)
	if results[0].Category != "custom" {
		t.Fatalf("category %q, want custom", results[0].Category)
	}
	if results[0].Severity != "high" {
		t.Fatalf("severity %q, want high", results[0].Severity)
	}
}
