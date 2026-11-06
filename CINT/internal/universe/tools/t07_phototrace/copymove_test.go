package t07_phototrace

import (
	"encoding/json"
	"image"
	"image/color"
	"testing"
)

func TestRegionJSONRoundTrip(t *testing.T) {
	r := Region{X1: 10, Y1: 20, X2: 100, Y2: 200, Score: 0.9, Hash: "deadbeef"}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var out Region
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if out.X1 != 10 || out.Y1 != 20 || out.X2 != 100 || out.Y2 != 200 {
		t.Fatalf("round-trip lost coords: %+v", out)
	}
}

func TestCopyMoveFlatImageBounded(t *testing.T) {
	img := image.NewRGBA(image.Rect(0, 0, 256, 256))
	for y := 0; y < 256; y++ {
		for x := 0; x < 256; x++ {
			img.Set(x, y, color.RGBA{128, 128, 128, 255})
		}
	}
	got := DetectCopyMove(img)
	if got == nil {
		t.Fatal("nil result")
	}
	if len(got.Regions) > cmMaxRegions {
		t.Fatalf("region cap violated: %d", len(got.Regions))
	}
}

func TestCopyMoveLargeImageTruncated(t *testing.T) {
	img := image.NewRGBA(image.Rect(0, 0, 10000, 10000))
	got := DetectCopyMove(img)
	if got == nil {
		t.Fatal("nil result")
	}
	if !got.Truncated {
		t.Fatalf("expected truncated for 100 MP image")
	}
	if len(got.Regions) != 0 {
		t.Fatalf("expected no scan")
	}
}
