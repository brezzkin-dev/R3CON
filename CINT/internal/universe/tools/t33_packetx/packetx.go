package t33_packetx

import (
	"fmt"
	"math"
	"sort"
	"strings"

	core "github.com/brezzkin-dev/CINT/internal/universe/core"
)

type flowKey struct {
	SrcIP, DstIP     string
	SrcPort, DstPort uint16
	Proto            uint8
}

func (k flowKey) String() string {
	return fmt.Sprintf("%s:%d-%s:%d/%d", k.SrcIP, k.SrcPort, k.DstIP, k.DstPort, k.Proto)
}

type flowStat struct {
	Key        flowKey
	Packets    int
	Bytes      int
	FirstTS    int64
	LastTS     int64
	Timestamps []int64
}

type credential struct {
	Src, Dst, Proto, Kind, User, Pass string
}

func Run(path string) (*core.Result, error) {
	r := core.NewResult("packetx", path)

	pkts, hdr, err := readPCAP(path)
	if err != nil {
		return r, err
	}
	r.AddExtra("link_type", hdr.Link)
	r.AddExtra("packet_count", len(pkts))

	flows := map[flowKey]*flowStat{}
	dnsQueries := map[string]int{}
	httpHosts := map[string]int{}
	httpURIs := []string{}
	tlsSNIs := map[string]int{}
	var creds []credential

	for _, pkt := range pkts {
		et, l3, ok := l2Payload(hdr.Link, pkt.Data)
		if !ok {
			continue
		}
		var proto uint8
		var srcIP, dstIP string
		var l4 []byte
		switch et {
		case 0x0800:
			proto, srcIP, dstIP, l4, ok = ipv4Parse(l3)
		case 0x86dd:
			proto, srcIP, dstIP, l4, ok = ipv6Parse(l3)
		default:
			continue
		}
		if !ok {
			continue
		}

		switch proto {
		case 6:
			sport, dport, payload, ok := tcpParse(l4)
			if !ok {
				continue
			}
			k := flowKey{srcIP, dstIP, sport, dport, 6}
			recordFlow(flows, k, len(payload), pkt.TS.Unix())
			if kind, v, ok := parseFTPUser(payload); ok {
				creds = append(creds, credential{
					Src: srcIP, Dst: dstIP, Proto: "ftp", Kind: kind,
					User: pick(kind == "user", v, ""),
					Pass: pick(kind == "pass", v, ""),
				})
			}
			if auth, ok := parseHTTPBasicAuth(payload); ok {
				creds = append(creds, credential{
					Src: srcIP, Dst: dstIP, Proto: "http", Kind: "basic",
					User: auth,
				})
			}
			if host, uri, _, ok := parseHTTPHost(payload); ok {
				httpHosts[host]++
				if len(httpURIs) < 100 {
					httpURIs = append(httpURIs, formatURL("http", host, uri))
				}
			}
			if sni := parseTLSClientHelloSNI(payload); sni != "" {
				tlsSNIs[sni]++
			}
		case 17:
			sport, dport, payload, ok := udpParse(l4)
			if !ok {
				continue
			}
			k := flowKey{srcIP, dstIP, sport, dport, 17}
			recordFlow(flows, k, len(payload), pkt.TS.Unix())
			if dport == 53 && len(payload) > 12 {
				if q := parseDNSQuestion(payload); q != "" {
					dnsQueries[q]++
				}
			}
		}
	}

	topSrc := topBy(func() map[string]int {
		m := map[string]int{}
		for _, f := range flows {
			m[f.Key.SrcIP] += f.Bytes
		}
		return m
	}(), 20)
	topDst := topBy(func() map[string]int {
		m := map[string]int{}
		for _, f := range flows {
			m[f.Key.DstIP] += f.Bytes
		}
		return m
	}(), 20)
	r.AddExtra("top_src", topSrc)
	r.AddExtra("top_dst", topDst)

	beacons := detectBeacons(flows)
	for _, b := range beacons {
		r.Add(core.Finding{
			Tool: "packetx", Severity: core.SevHigh,
			Title: "Periodic beacon",
			Detail: fmt.Sprintf("%s every %.1fs (jitter %.1f%%)",
				b.Key.String(), b.MeanSec, b.JitterPct),
		})
	}
	r.AddExtra("beacons", beacons)

	if len(creds) > 0 {
		r.Add(core.Finding{
			Tool: "packetx", Severity: core.SevCrit,
			Title:  fmt.Sprintf("%d cleartext credentials", len(creds)),
			Detail: "credentials sent unencrypted",
		})
	}
	r.AddExtra("credentials", creds)

	if len(dnsQueries) > 0 {
		r.AddExtra("dns", topBy(dnsQueries, 100))
	}
	if len(httpHosts) > 0 {
		r.AddExtra("http_hosts", topBy(httpHosts, 50))
	}
	if len(httpURIs) > 0 {
		r.AddExtra("http_uris_sample", httpURIs)
	}
	if len(tlsSNIs) > 0 {
		r.AddExtra("tls_sni", topBy(tlsSNIs, 50))
	}

	r.Finish()
	return r, nil
}

func pick(cond bool, a, b string) string {
	if cond {
		return a
	}
	return b
}

func recordFlow(flows map[flowKey]*flowStat, k flowKey, bytes int, ts int64) {
	f, ok := flows[k]
	if !ok {
		f = &flowStat{Key: k, FirstTS: ts}
		flows[k] = f
	}
	f.Packets++
	f.Bytes += bytes
	if ts > f.LastTS {
		f.LastTS = ts
	}
	if len(f.Timestamps) < 100 {
		f.Timestamps = append(f.Timestamps, ts)
	}
}

func topBy(m map[string]int, n int) []map[string]any {
	type kv struct {
		k string
		v int
	}
	var arr []kv
	for k, v := range m {
		arr = append(arr, kv{k, v})
	}
	sort.Slice(arr, func(i, j int) bool { return arr[i].v > arr[j].v })
	if len(arr) > n {
		arr = arr[:n]
	}
	out := make([]map[string]any, len(arr))
	for i, e := range arr {
		out[i] = map[string]any{"name": e.k, "count": e.v}
	}
	return out
}

type beacon struct {
	Key       flowKey
	MeanSec   float64
	JitterPct float64
	Count     int
}

func detectBeacons(flows map[flowKey]*flowStat) []beacon {
	var out []beacon
	for _, f := range flows {
		if len(f.Timestamps) < 6 {
			continue
		}
		ts := f.Timestamps
		var deltas []float64
		for i := 1; i < len(ts); i++ {
			d := float64(ts[i] - ts[i-1])
			if d > 0 {
				deltas = append(deltas, d)
			}
		}
		if len(deltas) < 5 {
			continue
		}
		var sum float64
		for _, d := range deltas {
			sum += d
		}
		mean := sum / float64(len(deltas))
		if mean < 5 || mean > 1800 {
			continue
		}
		var varSum float64
		for _, d := range deltas {
			diff := d - mean
			varSum += diff * diff
		}
		std := math.Sqrt(varSum / float64(len(deltas)))
		cv := std / mean
		if cv < 0.15 {
			out = append(out, beacon{
				Key: f.Key, MeanSec: mean,
				JitterPct: cv * 100, Count: f.Packets,
			})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].JitterPct < out[j].JitterPct })
	if len(out) > 20 {
		out = out[:20]
	}
	return out
}

var _ = strings.TrimSpace
