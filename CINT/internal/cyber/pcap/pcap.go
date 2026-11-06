package pcap

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strings"

	core "github.com/brezzkin-dev/CINT/internal/cyber/core"
)

type pktTS struct {
	TS  float64
	Key string
}

type portPkt struct {
	Src, Dst string
	DstPort  uint16
	Proto    uint8
}

type credential struct {
	Src   string `json:"src"`
	Dst   string `json:"dst"`
	Proto string `json:"proto"`
	Kind  string `json:"kind"`
	User  string `json:"user,omitempty"`
	Pass  string `json:"pass,omitempty"`
}

func readPCAP(data []byte) ([][]byte, bool, error) {
	if len(data) < 24 {
		return nil, false, fmt.Errorf("short pcap")
	}
	magic := binary.LittleEndian.Uint32(data[0:4])
	var le bool
	switch magic {
	case 0xa1b2c3d4, 0xa1b23c4d:
		le = true
	case 0xd4c3b2a1, 0x4d3cb2a1:
		le = false
	default:
		return nil, false, fmt.Errorf("bad magic")
	}
	var order binary.ByteOrder = binary.LittleEndian
	if !le {
		order = binary.BigEndian
	}
	off := 24
	var pkts [][]byte
	for off+16 <= len(data) {
		incl := int(order.Uint32(data[off+8 : off+12]))
		off += 16
		if off+incl > len(data) {
			break
		}
		pkts = append(pkts, data[off:off+incl])
		off += incl
	}
	return pkts, le, nil
}

func parseFrame(pkt []byte) (proto uint8, srcIP, dstIP string, sport, dport uint16, payload []byte) {
	if len(pkt) < 14 {
		return
	}
	et := binary.BigEndian.Uint16(pkt[12:14])

	var ip []byte
	switch et {
	case 0x0800:
		ip = pkt[14:]
	case 0x86dd:
		if len(pkt) < 14+40 {
			return
		}
		ip6 := pkt[14:]
		proto = ip6[6]
		srcIP = net.IP(ip6[8:24]).String()
		dstIP = net.IP(ip6[24:40]).String()
		l4 := ip6[40:]
		parseL4(proto, l4, &sport, &dport, &payload)
		return
	default:
		return
	}

	if len(ip) < 20 {
		return
	}
	ihl := int(ip[0]&0x0f) * 4
	if len(ip) < ihl {
		return
	}
	proto = ip[9]
	srcIP = net.IP(ip[12:16]).String()
	dstIP = net.IP(ip[16:20]).String()
	parseL4(proto, ip[ihl:], &sport, &dport, &payload)
	return
}

func parseL4(proto uint8, l4 []byte, sport, dport *uint16, payload *[]byte) {
	switch proto {
	case 6:
		if len(l4) < 20 {
			return
		}
		*sport = binary.BigEndian.Uint16(l4[0:2])
		*dport = binary.BigEndian.Uint16(l4[2:4])
		doff := int((l4[12]>>4)&0x0f) * 4
		if len(l4) >= doff {
			*payload = l4[doff:]
		}
	case 17:
		if len(l4) < 8 {
			return
		}
		*sport = binary.BigEndian.Uint16(l4[0:2])
		*dport = binary.BigEndian.Uint16(l4[2:4])
		plen := int(binary.BigEndian.Uint16(l4[4:6]))
		if plen >= 8 && len(l4) >= plen {
			*payload = l4[8:plen]
		}
	}
}

func extractCreds(proto uint8, src, dst string, sport, dport uint16, payload []byte) []credential {
	var out []credential
	if len(payload) == 0 {
		return out
	}
	up := strings.ToUpper(string(payload))

	if dport == 21 || sport == 21 {
		if strings.HasPrefix(up, "USER ") {
			out = append(out, credential{Src: src, Dst: dst, Proto: "ftp", Kind: "user",
				User: strings.TrimSpace(string(payload[5:]))})
		} else if strings.HasPrefix(up, "PASS ") {
			out = append(out, credential{Src: src, Dst: dst, Proto: "ftp", Kind: "pass",
				Pass: strings.TrimSpace(string(payload[5:]))})
		}
	}

	if dport == 25 || dport == 587 || sport == 25 || sport == 587 {
		if strings.HasPrefix(up, "AUTH PLAIN ") {
			rest := strings.TrimSpace(string(payload[11:]))
			if dec, err := decodeBase64(rest); err == nil {
				parts := strings.Split(dec, "\x00")
				if len(parts) == 3 {
					out = append(out, credential{Src: src, Dst: dst, Proto: "smtp", Kind: "auth",
						User: parts[1], Pass: parts[2]})
				}
			}
		}
	}

	if dport == 110 || sport == 110 {
		if strings.HasPrefix(up, "USER ") {
			out = append(out, credential{Src: src, Dst: dst, Proto: "pop3", Kind: "user",
				User: strings.TrimSpace(string(payload[5:]))})
		} else if strings.HasPrefix(up, "PASS ") {
			out = append(out, credential{Src: src, Dst: dst, Proto: "pop3", Kind: "pass",
				Pass: strings.TrimSpace(string(payload[5:]))})
		}
	}

	if dport == 6667 || dport == 6697 {
		if strings.HasPrefix(up, "PASS ") {
			out = append(out, credential{Src: src, Dst: dst, Proto: "irc", Kind: "pass",
				Pass: strings.TrimSpace(string(payload[5:]))})
		}
	}

	if dport == 80 || sport == 80 || dport == 8080 || sport == 8080 {
		if strings.HasPrefix(up, "GET ") || strings.HasPrefix(up, "POST ") {
			head := string(payload)
			if i := strings.Index(head, "\r\n"); i > 0 {
				head = head[:i]
			}
			lc := strings.ToLower(head)
			if idx := strings.Index(lc, "authorization: basic "); idx >= 0 {
				token := strings.TrimSpace(head[idx+len("authorization: basic "):])
				out = append(out, credential{Src: src, Dst: dst, Proto: "http", Kind: "basic", User: token})
			}
		}
	}

	return out
}

func decodeBase64(s string) (string, error) {
	var b strings.Builder
	for _, c := range s {
		if c != ' ' && c != '\r' && c != '\n' && c != '\t' {
			b.WriteRune(c)
		}
	}
	raw, err := decodeStd(b.String())
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

func parseDNSQuestion(d []byte) string {
	qd := binary.BigEndian.Uint16(d[4:6])
	if qd < 1 {
		return ""
	}
	off := 12
	var labels []string
	for off < len(d) {
		l := int(d[off])
		off++
		if l == 0 {
			break
		}
		if off+l > len(d) {
			break
		}
		labels = append(labels, string(d[off:off+l]))
		off += l
	}
	return strings.Join(labels, ".")
}

func tlsSNI(data []byte) string {
	if len(data) < 43 || data[0] != 0x16 || data[5] != 0x01 {
		return ""
	}
	off := 5 + 4 + 2 + 32
	if off >= len(data) {
		return ""
	}
	sidLen := int(data[off])
	off += 1 + sidLen
	if off+2 > len(data) {
		return ""
	}
	csLen := int(binary.BigEndian.Uint16(data[off : off+2]))
	off += 2 + csLen
	if off+1 > len(data) {
		return ""
	}
	cmLen := int(data[off])
	off += 1 + cmLen
	if off+2 > len(data) {
		return ""
	}
	extTotal := int(binary.BigEndian.Uint16(data[off : off+2]))
	off += 2
	end := off + extTotal
	if end > len(data) {
		end = len(data)
	}
	for off+4 <= end {
		et := binary.BigEndian.Uint16(data[off : off+2])
		el := int(binary.BigEndian.Uint16(data[off+2 : off+4]))
		off += 4
		if et == 0 && off+el <= len(data) && el >= 5 {
			body := data[off : off+el]
			nameLen := int(binary.BigEndian.Uint16(body[3:5]))
			if 5+nameLen <= len(body) {
				return string(body[5 : 5+nameLen])
			}
		}
		off += el
	}
	return ""
}

func Analyze(path string) (*core.Result, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	r := core.NewResult("pcap", path)
	pkts, _, err := readPCAP(data)
	if err != nil {
		r.Add(core.Finding{Tool: "pcap", Severity: core.SevHigh,
			Title: "parse error", Detail: err.Error()})
		r.Finish()
		return r, nil
	}

	var flowPkts []pktTS
	var scanPkts []portPkt
	var creds []credential
	dnsNames := map[string]int{}
	snis := map[string]int{}
	httpHosts := map[string]int{}

	for i, pkt := range pkts {
		proto, src, dst, sport, dport, payload := parseFrame(pkt)
		if src == "" {
			continue
		}
		key := fmt.Sprintf("%s:%d-%s:%d/%d", src, sport, dst, dport, proto)
		flowPkts = append(flowPkts, pktTS{TS: float64(i), Key: key})
		if proto == 6 {
			scanPkts = append(scanPkts, portPkt{Src: src, Dst: dst, DstPort: dport, Proto: 6})
		}

		if proto == 17 && dport == 53 && len(payload) > 12 {
			if name := parseDNSQuestion(payload); name != "" {
				dnsNames[name]++
			}
		}
		if proto == 6 && (dport == 443 || dport == 8443) && len(payload) > 5 && payload[0] == 0x16 {
			if sni := tlsSNI(payload); sni != "" {
				snis[sni]++
			}
		}
		if proto == 6 && (dport == 80 || dport == 8080) && len(payload) > 5 {
			s := string(payload)
			if strings.HasPrefix(s, "GET ") || strings.HasPrefix(s, "POST ") ||
				strings.HasPrefix(s, "HEAD ") || strings.HasPrefix(s, "PUT ") {
				for _, line := range strings.Split(s, "\r\n") {
					if strings.HasPrefix(strings.ToLower(line), "host:") {
						httpHosts[strings.TrimSpace(line[5:])]++
						break
					}
				}
			}
		}

		creds = append(creds, extractCreds(proto, src, dst, sport, dport, payload)...)
	}

	if len(creds) > 0 {
		r.Add(core.Finding{
			Tool: "pcap", Severity: core.SevCrit,
			Title:    fmt.Sprintf("%d credentials in cleartext", len(creds)),
			Detail:   "passwords transmitted without encryption",
			Evidence: map[string]any{"creds": creds},
		})
	}

	beacons := detectBeacons(flowPkts, 20)
	for _, b := range beacons {
		r.Add(core.Finding{
			Tool: "pcap", Severity: core.SevHigh,
			Title:    "Possible C2 beacon",
			Detail:   fmt.Sprintf("%s every %.1fs (jitter %.1f%%)", b.Key, b.MeanSeconds, b.JitterPct),
			Evidence: map[string]any{"mean_s": b.MeanSeconds, "jitter_pct": b.JitterPct, "count": b.Count},
		})
	}

	scans := detectPortScans(scanPkts)
	for _, s := range scans {
		r.Add(core.Finding{
			Tool: "pcap", Severity: core.SevHigh,
			Title:    "Port scan detected",
			Detail:   fmt.Sprintf("%s touched %d ports across %d hosts", s.Src, s.DistinctPorts, s.DistinctDst),
			Evidence: map[string]any{"src": s.Src, "distinct_ports": s.DistinctPorts, "distinct_dst": s.DistinctDst},
		})
	}

	r.AddExtra("packet_count", len(pkts))
	r.AddExtra("creds", creds)
	r.AddExtra("beacons", beacons)
	r.AddExtra("port_scans", scans)
	r.AddExtra("dns_top", topN(dnsNames, 20))
	r.AddExtra("sni_top", topN(snis, 20))
	r.AddExtra("http_hosts", topN(httpHosts, 20))
	r.Finish()
	return r, nil
}

func topN(m map[string]int, n int) []map[string]any {
	type kv struct {
		k string
		v int
	}
	var arr []kv
	for k, v := range m {
		arr = append(arr, kv{k, v})
	}
	for i := 0; i < len(arr); i++ {
		for j := i + 1; j < len(arr); j++ {
			if arr[j].v > arr[i].v {
				arr[i], arr[j] = arr[j], arr[i]
			}
		}
	}
	if len(arr) > n {
		arr = arr[:n]
	}
	out := make([]map[string]any, len(arr))
	for i, e := range arr {
		out[i] = map[string]any{"name": e.k, "count": e.v}
	}
	return out
}

func decodeStd(s string) ([]byte, error) {
	return base64Std.DecodeString(s)
}
