package t41_wifianalyze

import (
	"encoding/binary"
	"fmt"
	"os"
	"strings"
	"time"

	core "github.com/brezzkin-dev/CINT/internal/universe/core"
)

const (
	linkRadiotap = 127
	linkWifi     = 105
	linkPrism    = 119
)

type AP struct {
	BSSID      string `json:"bssid"`
	SSID       string `json:"ssid"`
	Channel    int    `json:"channel,omitempty"`
	RSSI       int    `json:"rssi,omitempty"`
	Beacons    int    `json:"beacons"`
	Encryption string `json:"encryption,omitempty"`
}

type Client struct {
	MAC        string   `json:"mac"`
	ProbeSSIDs []string `json:"probe_ssids,omitempty"`
	Count      int      `json:"count"`
}

type DeauthEvent struct {
	TS        string `json:"ts"`
	BSSID     string `json:"bssid"`
	ClientMAC string `json:"client_mac"`
	Reason    int    `json:"reason"`
}

type Handshake struct {
	BSSID     string `json:"bssid"`
	ClientMAC string `json:"client_mac"`
	Frames    int    `json:"frames"`
	Detected  string `json:"detected_at"`
}

func Run(path string) (*core.Result, error) {
	r := core.NewResult("wifi", path)

	data, err := os.ReadFile(path)
	if err != nil {
		return r, err
	}
	if len(data) < 24 {
		return r, fmt.Errorf("short pcap")
	}

	magic := binary.LittleEndian.Uint32(data[0:4])
	var endian binary.ByteOrder = binary.LittleEndian
	switch magic {
	case 0xa1b2c3d4, 0xa1b23c4d:
		endian = binary.LittleEndian
	case 0xd4c3b2a1, 0x4d3cb2a1:
		endian = binary.BigEndian
	default:
		return r, fmt.Errorf("not a pcap (magic 0x%08x)", magic)
	}
	linkType := endian.Uint32(data[20:24])
	r.AddExtra("link_type", linkType)
	if linkType != linkRadiotap && linkType != linkWifi && linkType != linkPrism {
		return r, fmt.Errorf("link type %d is not 802.11", linkType)
	}

	aps := map[string]*AP{}
	clients := map[string]*Client{}
	var deauthEvents []DeauthEvent
	handshakes := map[string]*Handshake{}

	type deauthBurst struct {
		bssid string
		start time.Time
		count int
	}
	var bursts []deauthBurst

	off := 24
	for off+16 <= len(data) {
		sec := endian.Uint32(data[off : off+4])
		frac := endian.Uint32(data[off+4 : off+8])
		incl := int(endian.Uint32(data[off+8 : off+12]))
		off += 16
		if off+incl > len(data) {
			break
		}
		pkt := data[off : off+incl]
		off += incl
		ts := time.Unix(int64(sec), int64(frac)*1000)

		var w []byte
		switch linkType {
		case linkRadiotap:
			if len(pkt) < 4 {
				continue
			}
			rtLen := int(binary.LittleEndian.Uint16(pkt[2:4]))
			if rtLen < 8 || rtLen >= len(pkt) {
				continue
			}
			w = pkt[rtLen:]
		case linkWifi:
			w = pkt
		case linkPrism:
			if len(pkt) < 144 {
				continue
			}
			w = pkt[144:]
		}
		if len(w) < 24 {
			continue
		}

		fc := binary.LittleEndian.Uint16(w[0:2])
		frameType := (fc >> 2) & 0x03
		subtype := (fc >> 4) & 0x0f

		if frameType == 0 {
			src := macStr(w[10:16])
			dst := macStr(w[4:10])

			switch subtype {
			case 8:
				if len(w) >= 36 {
					ssid := extractSSID(w[36:])
					a := getOrCreateAP(aps, src)
					a.SSID = ssid
					a.Beacons++
				}
			case 4:
				c := getOrCreateClient(clients, src)
				c.Count++
				if len(w) >= 28 {
					ssid := extractSSID(w[24:])
					if ssid != "" && !contains(c.ProbeSSIDs, ssid) {
						c.ProbeSSIDs = append(c.ProbeSSIDs, ssid)
					}
				}
			case 5:
				if len(w) >= 36 {
					ssid := extractSSID(w[36:])
					a := getOrCreateAP(aps, src)
					if a.SSID == "" {
						a.SSID = ssid
					}
				}
			case 12:
				reason := 0
				if len(w) >= 26 {
					reason = int(binary.LittleEndian.Uint16(w[24:26]))
				}
				deauthEvents = append(deauthEvents, DeauthEvent{
					TS:    ts.UTC().Format(time.RFC3339),
					BSSID: src, ClientMAC: dst, Reason: reason,
				})
				found := false
				for i := range bursts {
					if bursts[i].bssid == src && ts.Sub(bursts[i].start) < 10*time.Second {
						bursts[i].count++
						found = true
						break
					}
				}
				if !found {
					bursts = append(bursts, deauthBurst{bssid: src, start: ts, count: 1})
				}
			}
		}

		if frameType == 2 && len(w) >= 32 {
			for _, eapolOff := range []int{24 + 6, 24 + 6 + 8, 30 + 8} {
				if len(w) >= eapolOff+8 &&
					w[eapolOff] == 0xAA && w[eapolOff+1] == 0xAA &&
					w[eapolOff+2] == 0x03 &&
					w[eapolOff+6] == 0x88 && w[eapolOff+7] == 0x8e {
					src := macStr(w[10:16])
					dst := macStr(w[4:10])
					key := src + ":" + dst
					h, ok := handshakes[key]
					if !ok {
						h = &Handshake{BSSID: src, ClientMAC: dst,
							Detected: ts.UTC().Format(time.RFC3339)}
						handshakes[key] = h
					}
					h.Frames++
					break
				}
			}
		}
	}

	apList := make([]*AP, 0, len(aps))
	for _, a := range aps {
		apList = append(apList, a)
	}
	clientList := make([]*Client, 0, len(clients))
	for _, c := range clients {
		clientList = append(clientList, c)
	}
	handshakeList := make([]*Handshake, 0, len(handshakes))
	for _, h := range handshakes {
		handshakeList = append(handshakeList, h)
	}

	r.AddExtra("access_points", apList)
	r.AddExtra("clients", clientList)
	r.AddExtra("deauth_events", deauthEvents)
	r.AddExtra("handshakes", handshakeList)
	r.AddExtra("ap_count", len(aps))
	r.AddExtra("client_count", len(clients))

	for _, a := range apList {
		if a.SSID != "" {
			r.Add(core.Finding{Tool: "wifi", Severity: core.SevInfo,
				Title:  "AP: " + a.SSID,
				Detail: a.BSSID})
		}
	}
	for _, b := range bursts {
		if b.count >= 10 {
			r.Add(core.Finding{
				Tool: "wifi", Severity: core.SevHigh,
				Title:  "Possible deauth attack",
				Detail: fmt.Sprintf("%d deauth frames from %s in 10s window", b.count, b.bssid),
			})
		}
	}
	for _, h := range handshakeList {
		if h.Frames >= 4 {
			r.Add(core.Finding{
				Tool: "wifi", Severity: core.SevHigh,
				Title:  "WPA handshake complete",
				Detail: fmt.Sprintf("%s <-> %s (%d EAPOL frames)", h.BSSID, h.ClientMAC, h.Frames),
			})
		}
	}

	r.Finish()
	return r, nil
}

func macStr(b []byte) string {
	if len(b) < 6 {
		return ""
	}
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3], b[4], b[5])
}

func extractSSID(b []byte) string {
	if len(b) < 2 {
		return ""
	}
	id := b[0]
	length := int(b[1])
	if id != 0 || length > len(b)-2 {
		return ""
	}
	return string(b[2 : 2+length])
}

func getOrCreateAP(m map[string]*AP, bssid string) *AP {
	if a, ok := m[bssid]; ok {
		return a
	}
	a := &AP{BSSID: bssid}
	m[bssid] = a
	return a
}

func getOrCreateClient(m map[string]*Client, mac string) *Client {
	if c, ok := m[mac]; ok {
		return c
	}
	c := &Client{MAC: mac}
	m[mac] = c
	return c
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

var _ = strings.TrimSpace
