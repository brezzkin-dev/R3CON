package t14_geoarchive

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	core "github.com/brezzkin-dev/CINT/internal/universe/core"
)

func Run(coords, place string) (*core.Result, error) {
	r := core.NewResult("geoarchive", firstNonEmpty(coords, place))
	ctx := context.Background()

	var lat, lon float64
	if coords != "" {
		fmt.Sscanf(strings.ReplaceAll(coords, " ", ""), "%f,%f", &lat, &lon)
	} else if place != "" {
		url := fmt.Sprintf("https://nominatim.openstreetmap.org/search?format=json&q=%s", place)
		status, _, body, err := core.HTTPGet(ctx, url, map[string]string{"User-Agent": "CINT-OSINT/1.0"})
		if err != nil || status != 200 {
			return r, fmt.Errorf("geocode failed")
		}
		var out []map[string]any
		if json.Unmarshal(body, &out) == nil && len(out) > 0 {
			if v, ok := out[0]["lat"].(string); ok {
				fmt.Sscanf(v, "%f", &lat)
			}
			if v, ok := out[0]["lon"].(string); ok {
				fmt.Sscanf(v, "%f", &lon)
			}
			r.AddExtra("geocode", out[0])
		}
	}

	if lat == 0 && lon == 0 {
		return r, fmt.Errorf("could not determine coordinates")
	}
	r.AddExtra("lat", lat)
	r.AddExtra("lon", lon)

	revURL := fmt.Sprintf("https://nominatim.openstreetmap.org/reverse?format=json&lat=%f&lon=%f", lat, lon)
	if status, _, body, err := core.HTTPGet(ctx, revURL, map[string]string{"User-Agent": "CINT-OSINT/1.0"}); err == nil && status == 200 {
		var out map[string]any
		if json.Unmarshal(body, &out) == nil {
			r.AddExtra("reverse", out)
		}
	}

	overpass := fmt.Sprintf(`[out:json][timeout:20];(node(around:200,%f,%f);way(around:200,%f,%f););out tags 100;`, lat, lon, lat, lon)
	status, body, err := core.HTTPPost(ctx, "https://overpass-api.de/api/interpreter", "application/x-www-form-urlencoded",
		[]byte("data="+urlEncode(overpass)), nil)
	if err == nil && status == 200 {
		var out map[string]any
		if json.Unmarshal(body, &out) == nil {
			if elements, ok := out["elements"].([]any); ok {
				r.AddExtra("osm_nearby", elements)
			}
		}
	}

	wikiURL := fmt.Sprintf("https://en.wikipedia.org/w/api.php?action=query&list=geosearch&gscoord=%f|%f&gsradius=10000&gslimit=20&format=json", lat, lon)
	if status, _, body, err := core.HTTPGet(ctx, wikiURL, nil); err == nil && status == 200 {
		var out map[string]any
		if json.Unmarshal(body, &out) == nil {
			r.AddExtra("wikipedia", out)
		}
	}

	r.Finish()
	return r, nil
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

func urlEncode(s string) string {
	var b strings.Builder
	for _, c := range s {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~' {
			b.WriteRune(c)
		} else {
			b.WriteString(fmt.Sprintf("%%%02X", c))
		}
	}
	return b.String()
}
