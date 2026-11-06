package t02_geoint

import (
	"context"
	"encoding/json"
	"fmt"
	"image"
	_ "image/jpeg"
	_ "image/png"
	"os"
	"strings"

	core "github.com/brezzkin-dev/CINT/internal/universe/core"
	t07 "github.com/brezzkin-dev/CINT/internal/universe/tools/t07_phototrace"
)

type Options struct {
	IP     string
	Coords string
	Image  string
}

func Run(opts Options) (*core.Result, error) {
	r := core.NewResult("geoint", firstNonEmpty(opts.IP, opts.Coords, opts.Image))

	if opts.IP != "" {
		if err := geolocateIP(r, opts.IP); err != nil {
			return r, err
		}
	}
	if opts.Coords != "" {
		if err := reverseGeocode(r, opts.Coords); err != nil {
			r.Add(core.Finding{Tool: "geoint", Severity: core.SevLow,
				Title: "reverse geocode failed", Detail: err.Error()})
		}
	}
	if opts.Image != "" {
		if err := extractImageGPS(r, opts.Image); err != nil {
			return r, err
		}
	}
	r.Finish()
	return r, nil
}

func geolocateIP(r *core.Result, ip string) error {
	ctx := context.Background()
	url := fmt.Sprintf("http://ip-api.com/json/%s?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query", ip)
	status, _, body, err := core.HTTPGet(ctx, url, nil)
	if err != nil {
		return err
	}
	if status != 200 {
		return fmt.Errorf("ip-api http %d", status)
	}
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		return err
	}
	r.AddExtra("geolocation", out)
	if s, ok := out["status"].(string); ok && s == "success" {
		if lat, ok := out["lat"].(float64); ok {
			if lon, ok := out["lon"].(float64); ok {
				r.Add(core.Finding{
					Tool: "geoint", Severity: core.SevInfo,
					Title: "IP located",
					Detail: fmt.Sprintf("%.4f,%.4f — %s, %s", lat, lon,
						toStr(out["city"]), toStr(out["country"])),
					Evidence: map[string]any{"lat": lat, "lon": lon, "isp": out["isp"]},
				})
			}
		}
	}
	return nil
}

func reverseGeocode(r *core.Result, coords string) error {
	ctx := context.Background()
	lat, lon := splitCoords(coords)
	url := fmt.Sprintf("https://nominatim.openstreetmap.org/reverse?format=json&lat=%s&lon=%s", lat, lon)
	status, _, body, err := core.HTTPGet(ctx, url, map[string]string{"User-Agent": "CINT-OSINT/1.0"})
	if err != nil {
		return err
	}
	if status != 200 {
		return fmt.Errorf("nominatim http %d", status)
	}
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		return err
	}
	r.AddExtra("reverse_geocode", out)
	if addr, ok := out["display_name"].(string); ok {
		r.Add(core.Finding{
			Tool: "geoint", Severity: core.SevInfo,
			Title:  "Address resolved",
			Detail: addr,
		})
	}
	return nil
}

func extractImageGPS(r *core.Result, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	img, _, err := image.Decode(f)
	f.Close()
	if err != nil {
		return err
	}

	rawBytes, _ := os.ReadFile(path)
	exif := t07.ParseEXIF(rawBytes)
	if exif == nil {
		r.Add(core.Finding{Tool: "geoint", Severity: core.SevLow,
			Title: "No EXIF data in image"})
		r.Finish()
		return nil
	}
	r.AddExtra("exif", exif)

	if gpsDec, ok := exif["GPSDecimal"].([]float64); ok && len(gpsDec) == 2 {
		lat, lon := gpsDec[0], gpsDec[1]
		r.Add(core.Finding{
			Tool: "geoint", Severity: core.SevInfo,
			Title:    "GPS in EXIF",
			Detail:   fmt.Sprintf("%.6f,%.6f", lat, lon),
			Evidence: map[string]any{"lat": lat, "lon": lon},
		})
		if place := reverseGeocodeFromCoords(lat, lon); place != "" {
			r.AddExtra("gps_place", place)
		}
	}

	_ = img.Bounds()
	return nil
}

func reverseGeocodeFromCoords(lat, lon float64) string {
	ctx := context.Background()
	url := fmt.Sprintf("https://nominatim.openstreetmap.org/reverse?format=json&lat=%f&lon=%f", lat, lon)
	status, _, body, err := core.HTTPGet(ctx, url, map[string]string{"User-Agent": "CINT-OSINT/1.0"})
	if err != nil || status != 200 {
		return ""
	}
	var out map[string]any
	if json.Unmarshal(body, &out) != nil {
		return ""
	}
	if s, ok := out["display_name"].(string); ok {
		return s
	}
	return ""
}

func splitCoords(s string) (string, string) {
	s = strings.ReplaceAll(s, " ", "")
	parts := strings.SplitN(s, ",", 2)
	if len(parts) != 2 {
		return "0", "0"
	}
	return parts[0], parts[1]
}

func toStr(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}
