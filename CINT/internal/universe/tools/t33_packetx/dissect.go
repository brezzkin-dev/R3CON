package t33_packetx

import (
	"encoding/binary"
	"net/url"
	"strings"
)

func parseDNSQuestion(payload []byte) string {
	if len(payload) < 12 {
		return ""
	}
	qd := binary.BigEndian.Uint16(payload[4:6])
	if qd < 1 {
		return ""
	}
	off := 12
	var labels []string
	for off < len(payload) {
		l := int(payload[off])
		off++
		if l == 0 {
			break
		}
		if off+l > len(payload) {
			return ""
		}
		labels = append(labels, string(payload[off:off+l]))
		off += l
	}
	return strings.Join(labels, ".")
}

func parseHTTPHost(payload []byte) (host, uri, method string, ok bool) {
	if len(payload) < 10 {
		return
	}
	space := -1
	for i := 0; i < len(payload) && i < 10; i++ {
		if payload[i] == ' ' {
			space = i
			break
		}
	}
	if space < 0 {
		return
	}
	method = string(payload[:space])
	switch method {
	case "GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "PATCH", "CONNECT":
	default:
		return
	}
	uriStart := space + 1
	uriEnd := uriStart
	for uriEnd < len(payload) && payload[uriEnd] != ' ' && payload[uriEnd] != '\r' {
		uriEnd++
	}
	if uriEnd == uriStart {
		return
	}
	uri = string(payload[uriStart:uriEnd])
	head := string(payload)
	if idx := strings.Index(head, "\r\n\r\n"); idx > 0 {
		head = head[:idx]
	}
	for _, line := range strings.Split(head, "\r\n") {
		lc := strings.ToLower(line)
		if strings.HasPrefix(lc, "host:") {
			host = strings.TrimSpace(line[5:])
			break
		}
	}
	ok = host != ""
	return
}

func parseTLSClientHelloSNI(payload []byte) string {
	if len(payload) < 43 || payload[0] != 0x16 || payload[5] != 0x01 {
		return ""
	}
	off := 5 + 4 + 2 + 32
	if off >= len(payload) {
		return ""
	}
	sidLen := int(payload[off])
	off += 1 + sidLen
	if off+2 > len(payload) {
		return ""
	}
	csLen := int(binary.BigEndian.Uint16(payload[off : off+2]))
	off += 2 + csLen
	if off+1 > len(payload) {
		return ""
	}
	cmLen := int(payload[off])
	off += 1 + cmLen
	if off+2 > len(payload) {
		return ""
	}
	extLen := int(binary.BigEndian.Uint16(payload[off : off+2]))
	off += 2
	end := off + extLen
	if end > len(payload) {
		end = len(payload)
	}
	for off+4 <= end {
		extType := binary.BigEndian.Uint16(payload[off : off+2])
		extSize := int(binary.BigEndian.Uint16(payload[off+2 : off+4]))
		off += 4
		if extType == 0 && off+extSize <= end && extSize >= 5 {
			body := payload[off : off+extSize]
			nameLen := int(binary.BigEndian.Uint16(body[3:5]))
			if 5+nameLen <= len(body) {
				return string(body[5 : 5+nameLen])
			}
		}
		off += extSize
	}
	return ""
}

func parseFTPUser(payload []byte) (kind, value string, ok bool) {
	if len(payload) < 5 {
		return
	}
	s := string(payload)
	if strings.HasPrefix(s, "USER ") {
		v := strings.TrimRight(s[5:], "\r\n")
		return "user", v, true
	}
	if strings.HasPrefix(s, "PASS ") {
		v := strings.TrimRight(s[5:], "\r\n")
		return "pass", v, true
	}
	return
}

func parseHTTPBasicAuth(payload []byte) (string, bool) {
	if len(payload) < 20 {
		return "", false
	}
	head := string(payload)
	if idx := strings.Index(head, "\r\n\r\n"); idx > 0 {
		head = head[:idx]
	}
	for _, line := range strings.Split(head, "\r\n") {
		if strings.HasPrefix(strings.ToLower(line), "authorization: basic ") {
			return strings.TrimSpace(line[len("authorization: basic "):]), true
		}
	}
	return "", false
}

func formatURL(scheme, host, uri string) string {
	if host == "" {
		return uri
	}
	u := &url.URL{Scheme: scheme, Host: host, Path: uri}
	return u.String()
}
