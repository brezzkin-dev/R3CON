package t07_phototrace

import (
	"encoding/binary"
	"fmt"
)

// ParseEXIF walks the JPEG APP1 EXIF segment and extracts TIFF IFD tags.
// Returns nil when no EXIF is present or the segment is malformed.
func ParseEXIF(data []byte) map[string]any {
	off := findMarker(data, 0xFFE1)
	if off < 0 {
		return nil
	}
	hdrStart := off + 4
	if hdrStart+6 > len(data) {
		return nil
	}
	if string(data[hdrStart:hdrStart+6]) != "Exif\x00\x00" {
		return nil
	}
	tiff := data[hdrStart+6:]
	if len(tiff) < 8 {
		return nil
	}

	var le bool
	switch string(tiff[:2]) {
	case "II":
		le = true
	case "MM":
		le = false
	default:
		return nil
	}
	order := binary.ByteOrder(binary.BigEndian)
	if le {
		order = binary.LittleEndian
	}

	ifd0Offset := order.Uint32(tiff[4:8])
	if ifd0Offset+2 > uint32(len(tiff)) {
		return nil
	}

	out := map[string]any{}
	walkIFD(tiff, order, ifd0Offset, out, 0)
	return out
}

func findMarker(data []byte, marker uint16) int {
	hi, lo := byte(marker>>8), byte(marker&0xff)
	for i := 0; i < len(data)-1; i++ {
		if data[i] == hi && data[i+1] == lo {
			return i
		}
	}
	return -1
}

var tagNames = map[uint16]string{
	0x010F: "Make", 0x0110: "Model", 0x0112: "Orientation",
	0x011A: "XResolution", 0x011B: "YResolution",
	0x0128: "ResolutionUnit", 0x0131: "Software",
	0x0132: "DateTime", 0x013B: "Artist", 0x8298: "Copyright",
	0x9003: "DateTimeOriginal", 0x9004: "DateTimeDigitized",
	0x829A: "ExposureTime", 0x829D: "FNumber",
	0x8827: "ISOSpeedRatings", 0x920A: "FocalLength",
	0xA002: "PixelXDimension", 0xA003: "PixelYDimension",
	0x8825: "GPSInfoIFDPointer",
}

var typeSizes = map[uint16]int{
	1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 6: 1, 7: 1, 8: 2, 9: 4, 10: 8, 11: 4, 12: 8,
}

func walkIFD(tiff []byte, order binary.ByteOrder, off uint32, out map[string]any, depth int) {
	if depth > 3 || off+2 > uint32(len(tiff)) {
		return
	}
	count := order.Uint16(tiff[off : off+2])
	base := off + 2
	for i := uint16(0); i < count; i++ {
		entryOff := base + uint32(i)*12
		if entryOff+12 > uint32(len(tiff)) {
			return
		}
		tag := order.Uint16(tiff[entryOff : entryOff+2])
		typ := order.Uint16(tiff[entryOff+2 : entryOff+4])
		n := order.Uint32(tiff[entryOff+4 : entryOff+8])
		size, ok := typeSizes[typ]
		if !ok {
			continue
		}
		total := int(n) * size
		var valOff uint32
		if total <= 4 {
			valOff = entryOff + 8
		} else {
			valOff = order.Uint32(tiff[entryOff+8 : entryOff+12])
		}
		if valOff+uint32(total) > uint32(len(tiff)) {
			continue
		}
		name := tagNames[tag]
		if name == "" {
			name = fmt.Sprintf("tag_0x%04x", tag)
		}
		switch typ {
		case 2:
			s := tiff[valOff : valOff+uint32(total)]
			end := 0
			for end < len(s) && s[end] != 0 {
				end++
			}
			out[name] = string(s[:end])
		case 3:
			if n >= 1 {
				out[name] = order.Uint16(tiff[valOff : valOff+2])
			}
		case 4:
			if n >= 1 {
				out[name] = order.Uint32(tiff[valOff : valOff+4])
			}
		case 5:
			if n >= 1 && valOff+8 <= uint32(len(tiff)) {
				num := order.Uint32(tiff[valOff : valOff+4])
				den := order.Uint32(tiff[valOff+4 : valOff+8])
				if den != 0 {
					out[name] = float64(num) / float64(den)
				}
			}
		case 10:
			if n >= 1 && valOff+8 <= uint32(len(tiff)) {
				num := int32(order.Uint32(tiff[valOff : valOff+4]))
				den := int32(order.Uint32(tiff[valOff+4 : valOff+8]))
				if den != 0 {
					out[name] = float64(num) / float64(den)
				}
			}
		}

		if tag == 0x8825 && typ == 4 && n == 1 {
			gpsOff := order.Uint32(tiff[valOff : valOff+4])
			walkGPS(tiff, order, gpsOff, out)
		}
	}

	nextOff := base + uint32(count)*12
	if nextOff+4 <= uint32(len(tiff)) {
		next := order.Uint32(tiff[nextOff : nextOff+4])
		if next != 0 {
			walkIFD(tiff, order, next, out, depth+1)
		}
	}
}

var gpsTags = map[uint16]string{
	0x0000: "GPSVersionID", 0x0001: "GPSLatitudeRef", 0x0002: "GPSLatitude",
	0x0003: "GPSLongitudeRef", 0x0004: "GPSLongitude",
	0x0005: "GPSAltitudeRef", 0x0006: "GPSAltitude",
	0x0007: "GPSTimeStamp", 0x001D: "GPSDateStamp",
	0x0010: "GPSImgDirectionRef", 0x0011: "GPSImgDirection",
}

func walkGPS(tiff []byte, order binary.ByteOrder, off uint32, out map[string]any) {
	if off+2 > uint32(len(tiff)) {
		return
	}
	count := order.Uint16(tiff[off : off+2])
	base := off + 2
	gpsOut := map[string]any{}
	for i := uint16(0); i < count; i++ {
		entryOff := base + uint32(i)*12
		if entryOff+12 > uint32(len(tiff)) {
			return
		}
		tag := order.Uint16(tiff[entryOff : entryOff+2])
		typ := order.Uint16(tiff[entryOff+2 : entryOff+4])
		n := order.Uint32(tiff[entryOff+4 : entryOff+8])
		name := gpsTags[tag]
		if name == "" {
			continue
		}
		size, ok := typeSizes[typ]
		if !ok {
			continue
		}
		total := int(n) * size
		var valOff uint32
		if total <= 4 {
			valOff = entryOff + 8
		} else {
			valOff = order.Uint32(tiff[entryOff+8 : entryOff+12])
		}
		if valOff+uint32(total) > uint32(len(tiff)) {
			continue
		}
		switch typ {
		case 2:
			s := tiff[valOff : valOff+uint32(total)]
			end := 0
			for end < len(s) && s[end] != 0 {
				end++
			}
			gpsOut[name] = string(s[:end])
		case 5:
			if n == 3 && valOff+24 <= uint32(len(tiff)) {
				var deg, min, sec float64
				num := order.Uint32(tiff[valOff : valOff+4])
				den := order.Uint32(tiff[valOff+4 : valOff+8])
				if den != 0 {
					deg = float64(num) / float64(den)
				}
				num = order.Uint32(tiff[valOff+8 : valOff+12])
				den = order.Uint32(tiff[valOff+12 : valOff+16])
				if den != 0 {
					min = float64(num) / float64(den)
				}
				num = order.Uint32(tiff[valOff+16 : valOff+20])
				den = order.Uint32(tiff[valOff+20 : valOff+24])
				if den != 0 {
					sec = float64(num) / float64(den)
				}
				gpsOut[name] = []float64{deg, min, sec}
			}
		}
	}
	lat, latOK := gpsOut["GPSLatitude"].([]float64)
	lng, lngOK := gpsOut["GPSLongitude"].([]float64)
	if latOK && lngOK && len(lat) == 3 && len(lng) == 3 {
		latDec := lat[0] + lat[1]/60 + lat[2]/3600
		lngDec := lng[0] + lng[1]/60 + lng[2]/3600
		if r, ok := gpsOut["GPSLatitudeRef"].(string); ok && r == "S" {
			latDec = -latDec
		}
		if r, ok := gpsOut["GPSLongitudeRef"].(string); ok && r == "W" {
			lngDec = -lngDec
		}
		out["GPSDecimal"] = []float64{roundf(latDec, 6), roundf(lngDec, 6)}
	}
	if len(gpsOut) > 0 {
		out["GPS"] = gpsOut
	}
}
