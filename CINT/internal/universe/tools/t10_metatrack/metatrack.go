package t10_metatrack

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"os"
	"path/filepath"
	"strings"

	core "github.com/brezzkin-dev/CINT/internal/universe/core"
	t07 "github.com/brezzkin-dev/CINT/internal/universe/tools/t07_phototrace"
)

func Run(path string) (*core.Result, error) {
	r := core.NewResult("metatrack", path)
	stat, err := os.Stat(path)
	if err != nil {
		return r, err
	}
	r.AddExtra("size", stat.Size())
	r.AddExtra("mtime", stat.ModTime().UTC().Format("2006-01-02T15:04:05Z"))

	data, err := os.ReadFile(path)
	if err != nil {
		return r, err
	}
	md5h := md5.Sum(data)
	sha1h := sha1.Sum(data)
	sha256h := sha256.Sum256(data)
	r.AddExtra("md5", hex.EncodeToString(md5h[:]))
	r.AddExtra("sha1", hex.EncodeToString(sha1h[:]))
	r.AddExtra("sha256", hex.EncodeToString(sha256h[:]))

	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".jpg", ".jpeg", ".png", ".gif":
		exif := t07.ParseEXIF(data)
		if exif != nil {
			r.AddExtra("exif", exif)
			if sw, ok := exif["Software"].(string); ok && sw != "" {
				r.Add(core.Finding{Tool: "metatrack", Severity: core.SevMed,
					Title: "Software field present", Detail: sw})
			}
			if gps, ok := exif["GPSDecimal"].([]float64); ok && len(gps) == 2 {
				r.Add(core.Finding{Tool: "metatrack", Severity: core.SevMed,
					Title:  "GPS embedded",
					Detail: fmt.Sprintf("%.6f,%.6f", gps[0], gps[1])})
			}
			if m, ok := exif["Make"].(string); ok && m != "" {
				r.AddExtra("camera_make", m)
			}
			if m, ok := exif["Model"].(string); ok && m != "" {
				r.AddExtra("camera_model", m)
			}
			if dt, ok := exif["DateTimeOriginal"].(string); ok {
				r.AddExtra("date_original", dt)
			}
		}
		if img, _, err := image.Decode(strings.NewReader(string(data))); err == nil {
			b := img.Bounds()
			r.AddExtra("width", b.Dx())
			r.AddExtra("height", b.Dy())
		}
	case ".pdf":
		meta := parsePDFMeta(data)
		if len(meta) > 0 {
			r.AddExtra("pdf_meta", meta)
		}
	case ".mp3":
		if size, tag := parseID3(data); size > 0 {
			r.AddExtra("id3", tag)
		}
	case ".docx", ".xlsx", ".pptx", ".zip":
		zipNames := listZipEntries(data)
		if len(zipNames) > 0 {
			r.AddExtra("zip_entries", zipNames)
			for _, n := range zipNames {
				ln := strings.ToLower(n)
				if strings.HasSuffix(ln, "docprops/core.xml") ||
					strings.HasSuffix(ln, "docprops/app.xml") {
					r.Add(core.Finding{Tool: "metatrack", Severity: core.SevMed,
						Title: "Office metadata present", Detail: n})
				}
			}
		}
	}

	r.Finish()
	return r, nil
}

func parsePDFMeta(data []byte) map[string]any {
	out := map[string]any{}
	s := string(data)
	for _, key := range []string{"Author", "Creator", "Producer", "CreationDate", "ModDate", "Title", "Subject"} {
		needle := "/" + key
		idx := strings.Index(s, needle)
		if idx < 0 {
			continue
		}
		rest := s[idx+len(needle):]
		for len(rest) > 0 && (rest[0] == ' ' || rest[0] == '\n' || rest[0] == '\r' || rest[0] == '\t') {
			rest = rest[1:]
		}
		if len(rest) == 0 {
			continue
		}
		if rest[0] == '(' {
			end := strings.IndexByte(rest, ')')
			if end > 1 {
				out[key] = rest[1:end]
			}
		} else if rest[0] == '<' {
			end := strings.IndexByte(rest, '>')
			if end > 1 {
				out[key] = rest[1:end]
			}
		}
	}
	return out
}

func parseID3(data []byte) (int, map[string]any) {
	if len(data) < 10 || string(data[:3]) != "ID3" {
		return 0, nil
	}
	size := int(data[6])<<21 | int(data[7])<<14 | int(data[8])<<7 | int(data[9])
	size += 10
	tag := map[string]any{"version": fmt.Sprintf("2.%d.%d", data[3], data[4]), "size": size}
	return size, tag
}

func listZipEntries(data []byte) []string {
	idx := -1
	for i := len(data) - 22; i >= 0; i-- {
		if data[i] == 'P' && data[i+1] == 'K' && data[i+2] == 0x05 && data[i+3] == 0x06 {
			idx = i
			break
		}
	}
	if idx < 0 {
		return nil
	}
	cdOff := int(data[idx+16]) | int(data[idx+17])<<8 | int(data[idx+18])<<16 | int(data[idx+19])<<24
	var names []string
	i := cdOff
	for i+46 <= len(data) && data[i] == 'P' && data[i+1] == 'K' && data[i+2] == 0x01 && data[i+3] == 0x02 {
		nameLen := int(data[i+28]) | int(data[i+29])<<8
		extraLen := int(data[i+30]) | int(data[i+31])<<8
		commentLen := int(data[i+32]) | int(data[i+33])<<8
		if i+46+nameLen > len(data) {
			break
		}
		name := string(data[i+46 : i+46+nameLen])
		names = append(names, name)
		i += 46 + nameLen + extraLen + commentLen
		if len(names) >= 200 {
			break
		}
	}
	return names
}

var _ = json.Marshal
