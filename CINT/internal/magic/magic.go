package magic

type Sig struct {
	Offset int
	Magic  []byte
	MIME   string
	Desc   string
}

var Signatures = []Sig{
	{0, []byte("\xff\xd8\xff"), "image/jpeg", "JPEG"},
	{0, []byte("\x89PNG\r\n\x1a\n"), "image/png", "PNG"},
	{0, []byte("GIF87a"), "image/gif", "GIF87a"},
	{0, []byte("GIF89a"), "image/gif", "GIF89a"},
	{0, []byte("%PDF-"), "application/pdf", "PDF"},
	{0, []byte("PK\x03\x04"), "application/zip", "ZIP"},
	{0, []byte("PK\x05\x06"), "application/zip", "ZIP empty"},
	{0, []byte("PK\x07\x08"), "application/zip", "ZIP spanned"},
	{0, []byte("7z\xbc\xaf\x27\x1c"), "application/x-7z-compressed", "7z"},
	{0, []byte("Rar!\x1a\x07\x00"), "application/x-rar", "RAR v4"},
	{0, []byte("Rar!\x1a\x07\x01\x00"), "application/x-rar", "RAR v5"},
	{0, []byte("\x1f\x8b\x08"), "application/gzip", "GZIP"},
	{0, []byte("BZh"), "application/x-bzip2", "BZIP2"},
	{0, []byte("\xfd7zXZ\x00"), "application/x-xz", "XZ"},
	{0, []byte("MZ"), "application/x-dosexec", "PE/EXE"},
	{0, []byte("\x7fELF"), "application/x-elf", "ELF"},
	{0, []byte("\xca\xfe\xba\xbe"), "application/java-class", "Java class"},
	{0, []byte("\xfe\xed\xfa\xce"), "application/x-mach-binary", "Mach-O 32 LE"},
	{0, []byte("\xfe\xed\xfa\xcf"), "application/x-mach-binary", "Mach-O 64 LE"},
	{0, []byte("\xce\xfa\xed\xfe"), "application/x-mach-binary", "Mach-O 32 BE"},
	{0, []byte("\xcf\xfa\xed\xfe"), "application/x-mach-binary", "Mach-O 64 BE"},
	{0, []byte("SQLite format 3\x00"), "application/x-sqlite3", "SQLite"},
	{0, []byte("\x00\x01\x00\x00\x00"), "font/ttf", "TTF"},
	{0, []byte("OTTO"), "font/otf", "OTF"},
	{0, []byte("wOFF"), "font/woff", "WOFF"},
	{0, []byte("wOF2"), "font/woff2", "WOFF2"},
	{0, []byte("OggS"), "application/ogg", "OGG"},
	{0, []byte("fLaC"), "audio/flac", "FLAC"},
	{0, []byte("ID3"), "audio/mpeg", "MP3 ID3"},
	{0, []byte("\xff\xfb"), "audio/mpeg", "MP3"},
	{0, []byte("\xff\xf1"), "audio/aac", "AAC"},
	{0, []byte("\xff\xf9"), "audio/aac", "AAC"},
	{0, []byte("RIFF"), "application/x-riff", "RIFF (WAV/AVI)"},
	{0, []byte("\x00\x00\x01\xba"), "video/mpeg", "MPEG-PS"},
	{0, []byte("\x00\x00\x01\xb3"), "video/mpeg", "MPEG-VS"},
	{4, []byte("ftyp"), "video/mp4", "MP4"},
	{4, []byte("ftypisom"), "video/mp4", "MP4 isom"},
	{4, []byte("ftypmp42"), "video/mp4", "MP4 mp42"},
	{4, []byte("ftypM4V"), "video/x-m4v", "M4V"},
	{0, []byte("\x1a\x45\xdf\xa3"), "video/x-matroska", "MKV/WebM"},
	{0, []byte("BM"), "image/bmp", "BMP"},
	{0, []byte("II*\x00"), "image/tiff", "TIFF LE"},
	{0, []byte("MM\x00*"), "image/tiff", "TIFF BE"},
	{0, []byte("\x00\x00\x01\x00"), "image/x-icon", "ICO"},
	{0, []byte("\x00\x00\x02\x00"), "image/x-icon", "CUR"},
	{0, []byte("d8:announce"), "application/x-bittorrent", "Torrent"},
	{0, []byte("-----BEGIN "), "application/x-pem", "PEM"},
	{0, []byte("<?xml"), "application/xml", "XML"},
	{0, []byte("<!DOCTYPE html"), "text/html", "HTML5"},
	{0, []byte("<html"), "text/html", "HTML"},
	{0, []byte("#!"), "text/x-script", "shebang"},
	{0, []byte("CWS"), "application/x-shockwave-flash", "SWF compressed"},
	{0, []byte("FWS"), "application/x-shockwave-flash", "SWF"},
	{0, []byte("ZWS"), "application/x-shockwave-flash", "SWF LZMA"},
	{0, []byte("!<arch>\n"), "application/x-ar", "AR archive"},
	{0, []byte("\xed\xab\xee\xdb"), "application/x-rpm", "RPM"},
	{0, []byte("\x1f\x9d"), "application/x-compress", "COMPRESS"},
	{0, []byte("\x04\x22\x4d\x18"), "application/x-lz4", "LZ4"},
	{0, []byte("\x28\xb5\x2f\xfd"), "application/x-zstd", "ZSTD"},
	{0, []byte("\x00asm"), "application/wasm", "WebAssembly"},
}

func Detect(head []byte) (mime, desc string, ok bool) {
	for _, s := range Signatures {
		if s.Offset+len(s.Magic) > len(head) {
			continue
		}
		match := true
		for i, b := range s.Magic {
			if head[s.Offset+i] != b {
				match = false
				break
			}
		}
		if match {
			return s.MIME, s.Desc, true
		}
	}
	return "", "", false
}
