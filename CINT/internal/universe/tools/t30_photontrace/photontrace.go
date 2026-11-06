package t30_photontrace

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"image"
	_ "image/jpeg"
	_ "image/png"
	"math"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	core "github.com/brezzkin-dev/CINT/internal/universe/core"
	t07 "github.com/brezzkin-dev/CINT/internal/universe/tools/t07_phototrace"
)

type Options struct {
	URL     string
	File    string
	Compare string
}

func Run(opts Options) (*core.Result, error) {
	r := core.NewResult("photontrace", firstNonEmpty(opts.URL, opts.File))
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	var data []byte
	var source string

	if opts.File != "" {
		b, err := os.ReadFile(opts.File)
		if err != nil {
			return r, err
		}
		data = b
		source = opts.File
	} else if opts.URL != "" {
		if err := assertSafeURL(opts.URL); err != nil {
			return r, err
		}
		status, _, body, err := core.HTTPGet(ctx, opts.URL, map[string]string{
			"User-Agent": "Mozilla/5.0 (photontrace)",
			"Accept":     "image/*",
		})
		if err != nil {
			return r, err
		}
		if status != 200 {
			return r, fmt.Errorf("http %d", status)
		}
		data = body
		source = opts.URL
	} else {
		return r, fmt.Errorf("photontrace: -url or -file required")
	}

	img, fmtName, err := image.Decode(bytes.NewReader(data))
	if err != nil {
		return r, fmt.Errorf("decode: %w", err)
	}
	bounds := img.Bounds()
	r.AddExtra("source", source)
	r.AddExtra("format", fmtName)
	r.AddExtra("width", bounds.Dx())
	r.AddExtra("height", bounds.Dy())
	r.AddExtra("bytes", len(data))

	md5h := md5.Sum(data)
	r.AddExtra("md5", hex.EncodeToString(md5h[:]))

	if exif := t07.ParseEXIF(data); exif != nil {
		r.AddExtra("exif", exif)
		if gps, ok := exif["GPSDecimal"].([]float64); ok && len(gps) == 2 {
			r.Add(core.Finding{Tool: "photontrace", Severity: core.SevMed,
				Title:  "GPS embedded in image",
				Detail: fmt.Sprintf("%.6f,%.6f", gps[0], gps[1])})
		}
		if sw, ok := exif["Software"].(string); ok && sw != "" {
			r.Add(core.Finding{Tool: "photontrace", Severity: core.SevLow,
				Title: "Editing software in EXIF", Detail: sw})
		}
	}

	if opts.File != "" || source != "" {
		if ela, err := t07.ELA(source, img); err == nil && ela != nil {
			r.AddExtra("ela", ela)
			if ela.AnomalousRatio > 0.15 {
				r.Add(core.Finding{Tool: "photontrace", Severity: core.SevHigh,
					Title:  "ELA anomaly",
					Detail: fmt.Sprintf("%.1f%% pixels (heuristic)", ela.AnomalousRatio*100)})
			}
		}
	}
	if noise := t07.NoiseVariance(img); noise != nil {
		r.AddExtra("noise", noise)
		if noise.HeterogeneityScore > 0.5 {
			r.Add(core.Finding{Tool: "photontrace", Severity: core.SevHigh,
				Title:  "Noise variance heterogeneous",
				Detail: fmt.Sprintf("score %.2f (heuristic)", noise.HeterogeneityScore)})
		}
	}
	if chroma := t07.ChromaticAberration(img); chroma != nil {
		r.AddExtra("chroma", chroma)
		if chroma.ChannelDiscrepancy > 0.4 {
			r.Add(core.Finding{Tool: "photontrace", Severity: core.SevMed,
				Title:  "Chromatic aberration inconsistent",
				Detail: fmt.Sprintf("%.2f", chroma.ChannelDiscrepancy)})
		}
	}

	ah := aHash(img)
	dh := dHash(img)
	ph := pHash(img)
	r.AddExtra("ahash", ah)
	r.AddExtra("dhash", dh)
	r.AddExtra("phash", ph)

	if opts.Compare != "" {
		other, err := os.ReadFile(opts.Compare)
		if err != nil {
			r.Add(core.Finding{Tool: "photontrace", Severity: core.SevLow,
				Title: "compare file error", Detail: err.Error()})
		} else if otherImg, _, err := image.Decode(bytes.NewReader(other)); err == nil {
			r.AddExtra("compare", map[string]any{
				"ahash_distance":       hammingHex(ah, aHash(otherImg)),
				"dhash_distance":       hammingHex(dh, dHash(otherImg)),
				"phash_distance":       hammingHex(ph, pHash(otherImg)),
				"ahash_similarity_pct": hashSimPct(ah, aHash(otherImg)),
				"dhash_similarity_pct": hashSimPct(dh, dHash(otherImg)),
				"phash_similarity_pct": hashSimPct(ph, pHash(otherImg)),
			})
		}
	}

	r.Finish()
	return r, nil
}

func aHash(img image.Image) string {
	g := gray8x8(img)
	var sum float64
	for _, v := range g {
		sum += v
	}
	mean := sum / float64(len(g))
	var bits uint64
	for i, v := range g {
		if v > mean {
			bits |= 1 << uint(i)
		}
	}
	return fmt.Sprintf("%016x", bits)
}

func dHash(img image.Image) string {
	b := img.Bounds()
	w, h := b.Dx(), b.Dy()
	var bits uint64
	idx := 0
	for y := 0; y < 8; y++ {
		for x := 0; x < 8; x++ {
			x1 := b.Min.X + (x * w / 9)
			x2 := b.Min.X + ((x + 1) * w / 9)
			y1 := b.Min.Y + (y * h / 8)
			l := lum(img.At(x1, y1))
			r := lum(img.At(x2, y1))
			if l > r {
				bits |= 1 << uint(idx)
			}
			idx++
		}
	}
	return fmt.Sprintf("%016x", bits)
}

func pHash(img image.Image) string {
	b := img.Bounds()
	w, h := b.Dx(), b.Dy()
	const N = 32
	var gray [N][N]float64
	for y := 0; y < N; y++ {
		for x := 0; x < N; x++ {
			sx := b.Min.X + x*w/N
			sy := b.Min.Y + y*h/N
			gray[y][x] = lum(img.At(sx, sy))
		}
	}
	var dct [N][N]float64
	for y := 0; y < N; y++ {
		for u := 0; u < N; u++ {
			var s float64
			for x := 0; x < N; x++ {
				s += gray[y][x] * math.Cos(float64((2*x+1)*u)*math.Pi/(2*N))
			}
			dct[y][u] = s
		}
	}
	var dct2 [N][N]float64
	for x := 0; x < N; x++ {
		for v := 0; v < N; v++ {
			var s float64
			for y := 0; y < N; y++ {
				s += dct[y][x] * math.Cos(float64((2*y+1)*v)*math.Pi/(2*N))
			}
			dct2[v][x] = s
		}
	}
	var vals []float64
	for y := 0; y < 8; y++ {
		for x := 0; x < 8; x++ {
			if y == 0 && x == 0 {
				continue
			}
			vals = append(vals, dct2[y][x])
		}
	}
	sorted := make([]float64, len(vals))
	copy(sorted, vals)
	for i := 1; i < len(sorted); i++ {
		for j := i; j > 0 && sorted[j] < sorted[j-1]; j-- {
			sorted[j], sorted[j-1] = sorted[j-1], sorted[j]
		}
	}
	med := sorted[len(sorted)/2]
	var bits uint64
	idx := 0
	for y := 0; y < 8; y++ {
		for x := 0; x < 8; x++ {
			if y == 0 && x == 0 {
				continue
			}
			if dct2[y][x] > med {
				bits |= 1 << uint(idx)
			}
			idx++
		}
	}
	return fmt.Sprintf("%016x", bits)
}

func gray8x8(img image.Image) []float64 {
	b := img.Bounds()
	w, h := b.Dx(), b.Dy()
	out := make([]float64, 0, 64)
	for y := 0; y < 8; y++ {
		for x := 0; x < 8; x++ {
			sx := b.Min.X + x*w/8 + w/16
			sy := b.Min.Y + y*h/8 + h/16
			out = append(out, lum(img.At(sx, sy)))
		}
	}
	return out
}

func lum(c interface {
	RGBA() (uint32, uint32, uint32, uint32)
}) float64 {
	r, g, b, _ := c.RGBA()
	return 0.299*float64(r>>8) + 0.587*float64(g>>8) + 0.114*float64(b>>8)
}

func hammingHex(a, b string) int {
	if len(a) != len(b) {
		return -1
	}
	var n int
	for i := 0; i < len(a); i++ {
		x := hexNib(a[i]) ^ hexNib(b[i])
		for x != 0 {
			n++
			x &= x - 1
		}
	}
	return n
}

func hashSimPct(a, b string) float64 {
	d := hammingHex(a, b)
	if d < 0 {
		return 0
	}
	bits := len(a) * 4
	return 100.0 * (1 - float64(d)/float64(bits))
}

func hexNib(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	}
	return 0
}

func assertSafeURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("scheme %q not allowed", u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("empty host")
	}
	if ip := net.ParseIP(host); ip != nil {
		if isBlocked(ip) {
			return fmt.Errorf("destination %s blocked", ip)
		}
		return nil
	}
	addrs, err := net.LookupHost(host)
	if err != nil {
		return err
	}
	for _, a := range addrs {
		if ip := net.ParseIP(a); ip != nil && isBlocked(ip) {
			return fmt.Errorf("%s resolves to blocked %s", host, a)
		}
	}
	return nil
}

func isBlocked(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified()
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

var _ = strings.TrimSpace
