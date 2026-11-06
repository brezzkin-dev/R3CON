package magic

import "testing"

func TestDetectPNG(t *testing.T) {
	head := append([]byte("\x89PNG\r\n\x1a\n"), make([]byte, 100)...)
	mime, desc, ok := Detect(head)
	if !ok {
		t.Fatal("expected detection")
	}
	if mime != "image/png" || desc != "PNG" {
		t.Fatalf("got %s/%s", mime, desc)
	}
}

func TestDetectPDF(t *testing.T) {
	head := append([]byte("%PDF-1.7"), make([]byte, 100)...)
	mime, _, ok := Detect(head)
	if !ok || mime != "application/pdf" {
		t.Fatalf("pdf detect failed: %s/%v", mime, ok)
	}
}

func TestDetectELF(t *testing.T) {
	head := append([]byte("\x7fELF"), make([]byte, 100)...)
	mime, _, ok := Detect(head)
	if !ok || mime != "application/x-elf" {
		t.Fatalf("elf detect failed: %s/%v", mime, ok)
	}
}

func TestDetectPE(t *testing.T) {
	head := append([]byte("MZ"), make([]byte, 100)...)
	mime, _, ok := Detect(head)
	if !ok || mime != "application/x-dosexec" {
		t.Fatalf("pe detect failed: %s/%v", mime, ok)
	}
}

func TestDetectUnknown(t *testing.T) {
	head := []byte("this is not a known file format at all, just text content here")
	_, _, ok := Detect(head)
	if ok {
		t.Fatal("expected no detection on plain text")
	}
}

func TestDetectShort(t *testing.T) {
	if _, _, ok := Detect(nil); ok {
		t.Fatal("expected no detection on empty input")
	}
	if _, _, ok := Detect([]byte{0x89}); ok {
		t.Fatal("expected no detection on 1-byte input")
	}
}
