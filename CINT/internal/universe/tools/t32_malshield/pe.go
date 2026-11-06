package t32_malshield

import (
	"debug/pe"
	"fmt"
	"sort"
	"strings"
)

type peInfo struct {
	Machine     string   `json:"machine"`
	Subsystem   string   `json:"subsystem"`
	Timestamp   uint32   `json:"timestamp"`
	EntryPoint  uint32   `json:"entry_point"`
	ImageBase   uint64   `json:"image_base"`
	SizeImage   uint32   `json:"size_image"`
	NumSections int      `json:"num_sections"`
	Imphash     string   `json:"imphash"`
	Overlay     int64    `json:"overlay_bytes"`
	Sections    []peSec  `json:"sections"`
	ImportDLLs  []string `json:"import_dlls"`
	ImportFns   []string `json:"import_fns"`
}

type peSec struct {
	Name    string  `json:"name"`
	Entropy float64 `json:"entropy"`
	Size    uint32  `json:"size"`
	RawSize uint32  `json:"raw_size"`
}

func analyzePE(path string, data []byte) (*peInfo, error) {
	f, err := pe.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	info := &peInfo{
		Machine:     machineName(f.Machine),
		Timestamp:   f.FileHeader.TimeDateStamp,
		NumSections: len(f.Sections),
	}

	if opt, ok := f.OptionalHeader.(*pe.OptionalHeader64); ok {
		info.EntryPoint = opt.AddressOfEntryPoint
		info.ImageBase = opt.ImageBase
		info.SizeImage = opt.SizeOfImage
		info.Subsystem = subsystemName(opt.Subsystem)
	} else if opt, ok := f.OptionalHeader.(*pe.OptionalHeader32); ok {
		info.EntryPoint = opt.AddressOfEntryPoint
		info.ImageBase = uint64(opt.ImageBase)
		info.SizeImage = opt.SizeOfImage
		info.Subsystem = subsystemName(opt.Subsystem)
	}

	var lastEnd int64
	for _, s := range f.Sections {
		raw, _ := s.Data()
		end := int64(s.Offset) + int64(s.Size)
		if end > lastEnd {
			lastEnd = end
		}
		info.Sections = append(info.Sections, peSec{
			Name:    s.Name,
			Entropy: entropy(raw),
			Size:    s.VirtualSize,
			RawSize: s.Size,
		})
	}
	if int64(len(data)) > lastEnd {
		info.Overlay = int64(len(data)) - lastEnd
	}

	syms, _ := f.ImportedSymbols()
	seen := map[string]bool{}
	for _, sym := range syms {
		parts := strings.SplitN(sym, ".", 2)
		dll := "unknown"
		fn := sym
		if len(parts) == 2 {
			dll = parts[0]
			fn = parts[1]
		}
		if !seen["dll:"+dll] {
			seen["dll:"+dll] = true
			info.ImportDLLs = append(info.ImportDLLs, dll)
		}
		info.ImportFns = append(info.ImportFns, fn)
	}
	sort.Strings(info.ImportDLLs)
	info.Imphash = imphash(info.ImportFns)
	return info, nil
}

func imphash(fns []string) string {
	lower := make([]string, 0, len(fns))
	for _, f := range fns {
		lower = append(lower, strings.ToLower(f))
	}
	sort.Strings(lower)
	joined := strings.Join(lower, ",")
	var h uint64 = 14695981039346656037
	for i := 0; i < len(joined); i++ {
		h ^= uint64(joined[i])
		h *= 1099511628211
	}
	return hexU64(h)
}

func hexU64(v uint64) string {
	const hex = "0123456789abcdef"
	var buf [16]byte
	for i := 15; i >= 0; i-- {
		buf[i] = hex[v&0xf]
		v >>= 4
	}
	return string(buf[:])
}

func machineName(m uint16) string {
	switch m {
	case pe.IMAGE_FILE_MACHINE_AMD64:
		return "x86_64"
	case pe.IMAGE_FILE_MACHINE_I386:
		return "x86"
	case pe.IMAGE_FILE_MACHINE_ARM64:
		return "arm64"
	case pe.IMAGE_FILE_MACHINE_ARM:
		return "arm"
	}
	return fmt.Sprintf("unknown_0x%04x", m)
}

func subsystemName(s uint16) string {
	switch s {
	case 1:
		return "native"
	case 2:
		return "windows_gui"
	case 3:
		return "windows_console"
	}
	return fmt.Sprintf("unknown_%d", s)
}
