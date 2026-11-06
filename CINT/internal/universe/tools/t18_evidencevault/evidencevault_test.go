package t18_evidencevault

import (
	"os"
	"path/filepath"
	"testing"
)

func TestVaultRoundTrip(t *testing.T) {
	dir := t.TempDir()
	vault := filepath.Join(dir, "v")
	if _, err := Init(vault); err != nil {
		t.Fatal(err)
	}
	ev := filepath.Join(dir, "ev.bin")
	if err := os.WriteFile(ev, []byte("hello evidence"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Add(vault, ev, "sample"); err != nil {
		t.Fatal(err)
	}
	res, err := Verify(vault)
	if err != nil {
		t.Fatal(err)
	}
	if res.Extra["broken"].(int) != 0 {
		t.Fatalf("expected clean, broken=%v", res.Extra["broken"])
	}
}

func TestVaultDetectsBlobTamper(t *testing.T) {
	dir := t.TempDir()
	vault := filepath.Join(dir, "v")
	if _, err := Init(vault); err != nil {
		t.Fatal(err)
	}
	ev := filepath.Join(dir, "ev.bin")
	if err := os.WriteFile(ev, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Add(vault, ev, ""); err != nil {
		t.Fatal(err)
	}
	blobs, _ := os.ReadDir(filepath.Join(vault, "blobs"))
	if len(blobs) != 1 {
		t.Fatalf("expected 1 blob, got %d", len(blobs))
	}
	blobPath := filepath.Join(vault, "blobs", blobs[0].Name())
	if err := os.WriteFile(blobPath, []byte("tampered"), 0600); err != nil {
		t.Fatal(err)
	}
	res, _ := Verify(vault)
	if res.Extra["broken"].(int) == 0 {
		t.Fatalf("expected tamper detected")
	}
}

func TestVaultRejectsPathEscape(t *testing.T) {
	dir := t.TempDir()
	vault := filepath.Join(dir, "v")
	if _, err := Init(vault); err != nil {
		t.Fatal(err)
	}
	mf := `{
		"version": "1.1",
		"created": "2026-01-01T00:00:00Z",
		"entries": [{
			"added_at": "2026-01-01T00:00:00Z",
			"added_by": "x", "hostname": "x", "source_path": "/etc/passwd",
			"size": 100, "mtime": "2026-01-01T00:00:00Z",
			"sha256": "../etc/passwd", "md5_legacy": "",
			"blob_path": "../etc/passwd",
			"prev_hash": "genesis", "this_hash": "bad"
		}]
	}`
	if err := os.WriteFile(filepath.Join(vault, "manifest.json"), []byte(mf), 0600); err != nil {
		t.Fatal(err)
	}
	res, err := Verify(vault)
	if err != nil {
		t.Fatal(err)
	}
	if res.Extra["broken"].(int) == 0 {
		t.Fatalf("expected path escape detection")
	}
}
