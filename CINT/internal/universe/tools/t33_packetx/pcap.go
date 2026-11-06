package t33_packetx

import (
	"encoding/binary"
	"fmt"
	"os"
	"time"
)

type packet struct {
	TS   time.Time
	Data []byte
	Idx  int
}

type pcapHeader struct {
	Magic  uint32
	Endian binary.ByteOrder
	Nano   bool
	Link   uint32
}

func readPCAP(path string) ([]packet, pcapHeader, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, pcapHeader{}, err
	}
	if len(data) < 24 {
		return nil, pcapHeader{}, fmt.Errorf("short pcap")
	}

	var hdr pcapHeader
	magic := binary.LittleEndian.Uint32(data[0:4])
	switch magic {
	case 0xa1b2c3d4:
		hdr.Magic, hdr.Endian, hdr.Nano = magic, binary.LittleEndian, false
	case 0xd4c3b2a1:
		hdr.Magic, hdr.Endian, hdr.Nano = magic, binary.BigEndian, false
	case 0xa1b23c4d:
		hdr.Magic, hdr.Endian, hdr.Nano = magic, binary.LittleEndian, true
	case 0x4d3cb2a1:
		hdr.Magic, hdr.Endian, hdr.Nano = magic, binary.BigEndian, true
	default:
		return nil, hdr, fmt.Errorf("bad magic 0x%08x", magic)
	}
	hdr.Link = hdr.Endian.Uint32(data[20:24])

	off := 24
	var pkts []packet
	idx := 0
	for off+16 <= len(data) {
		sec := hdr.Endian.Uint32(data[off : off+4])
		frac := hdr.Endian.Uint32(data[off+4 : off+8])
		incl := int(hdr.Endian.Uint32(data[off+8 : off+12]))
		off += 16
		if off+incl > len(data) {
			break
		}
		var t time.Time
		if hdr.Nano {
			t = time.Unix(int64(sec), int64(frac))
		} else {
			t = time.Unix(int64(sec), int64(frac)*1000)
		}
		pkts = append(pkts, packet{
			TS: t, Data: append([]byte{}, data[off:off+incl]...), Idx: idx,
		})
		idx++
		off += incl
	}
	return pkts, hdr, nil
}

func l2Payload(link uint32, pkt []byte) (uint16, []byte, bool) {
	switch link {
	case 1:
		if len(pkt) < 14 {
			return 0, nil, false
		}
		et := binary.BigEndian.Uint16(pkt[12:14])
		return et, pkt[14:], true
	case 113:
		if len(pkt) < 16 {
			return 0, nil, false
		}
		et := binary.BigEndian.Uint16(pkt[14:16])
		return et, pkt[16:], true
	case 276:
		if len(pkt) < 20 {
			return 0, nil, false
		}
		et := binary.BigEndian.Uint16(pkt[0:2])
		return et, pkt[20:], true
	}
	return 0, nil, false
}

func ipv4Parse(ip []byte) (proto uint8, src, dst string, l4 []byte, ok bool) {
	if len(ip) < 20 || ip[0]>>4 != 4 {
		return
	}
	ihl := int(ip[0]&0x0f) * 4
	if len(ip) < ihl {
		return
	}
	proto = ip[9]
	src = fmt.Sprintf("%d.%d.%d.%d", ip[12], ip[13], ip[14], ip[15])
	dst = fmt.Sprintf("%d.%d.%d.%d", ip[16], ip[17], ip[18], ip[19])
	l4 = ip[ihl:]
	ok = true
	return
}

func ipv6Parse(ip []byte) (proto uint8, src, dst string, l4 []byte, ok bool) {
	if len(ip) < 40 || ip[0]>>4 != 6 {
		return
	}
	proto = ip[6]
	src = ipv6String(ip[8:24])
	dst = ipv6String(ip[24:40])
	l4 = ip[40:]
	ok = true
	return
}

func ipv6String(b []byte) string {
	if len(b) != 16 {
		return ""
	}
	return fmt.Sprintf("%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
		b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
		b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15])
}

func tcpParse(tcp []byte) (sport, dport uint16, payload []byte, ok bool) {
	if len(tcp) < 20 {
		return
	}
	sport = binary.BigEndian.Uint16(tcp[0:2])
	dport = binary.BigEndian.Uint16(tcp[2:4])
	doff := int((tcp[12]>>4)&0x0f) * 4
	if doff < 20 || len(tcp) < doff {
		return
	}
	payload = tcp[doff:]
	ok = true
	return
}

func udpParse(udp []byte) (sport, dport uint16, payload []byte, ok bool) {
	if len(udp) < 8 {
		return
	}
	sport = binary.BigEndian.Uint16(udp[0:2])
	dport = binary.BigEndian.Uint16(udp[2:4])
	length := int(binary.BigEndian.Uint16(udp[4:6]))
	if length < 8 || len(udp) < length {
		payload = udp[8:]
	} else {
		payload = udp[8:length]
	}
	ok = true
	return
}
