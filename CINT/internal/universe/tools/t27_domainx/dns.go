package t27_domainx

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"
)

const (
	dnsTypeA      uint16 = 1
	dnsTypeNS     uint16 = 2
	dnsTypeCNAME  uint16 = 5
	dnsTypeSOA    uint16 = 6
	dnsTypeMX     uint16 = 15
	dnsTypeTXT    uint16 = 16
	dnsTypeAAAA   uint16 = 28
	dnsTypeSRV    uint16 = 33
	dnsTypeDNSKEY uint16 = 48
	dnsTypeDS     uint16 = 43
	dnsTypeCAA    uint16 = 257
	dnsTypeNAPTR  uint16 = 35
)

type dnsAnswer struct {
	Name  string
	Type  uint16
	TTL   uint32
	RDATA []byte
}

func queryDNS(server, domain string, qtype uint16, timeout time.Duration) ([]dnsAnswer, error) {
	var id [2]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	buf.Write(id[:])
	binary.Write(&buf, binary.BigEndian, uint16(0x0100))
	binary.Write(&buf, binary.BigEndian, uint16(1))
	binary.Write(&buf, binary.BigEndian, uint16(0))
	binary.Write(&buf, binary.BigEndian, uint16(0))
	binary.Write(&buf, binary.BigEndian, uint16(0))
	for _, label := range strings.Split(strings.TrimSuffix(domain, "."), ".") {
		if len(label) == 0 || len(label) > 63 {
			return nil, fmt.Errorf("invalid label %q", label)
		}
		buf.WriteByte(byte(len(label)))
		buf.WriteString(label)
	}
	buf.WriteByte(0)
	binary.Write(&buf, binary.BigEndian, qtype)
	binary.Write(&buf, binary.BigEndian, uint16(1))

	conn, err := net.DialTimeout("udp", server, timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(buf.Bytes()); err != nil {
		return nil, err
	}
	resp := make([]byte, 4096)
	n, err := conn.Read(resp)
	if err != nil {
		return nil, err
	}
	resp = resp[:n]
	if len(resp) < 12 {
		return nil, fmt.Errorf("short response")
	}
	if !bytes.Equal(resp[0:2], id[:]) {
		return nil, fmt.Errorf("id mismatch")
	}
	ancount := int(binary.BigEndian.Uint16(resp[6:8]))
	off := 12
	_, off, err = readName(resp, off)
	if err != nil {
		return nil, err
	}
	off += 4
	var answers []dnsAnswer
	for i := 0; i < ancount; i++ {
		name, noff, err := readName(resp, off)
		if err != nil {
			return nil, err
		}
		if noff+10 > len(resp) {
			return nil, fmt.Errorf("truncated answer")
		}
		t := binary.BigEndian.Uint16(resp[noff : noff+2])
		ttl := binary.BigEndian.Uint32(resp[noff+4 : noff+8])
		rdlen := int(binary.BigEndian.Uint16(resp[noff+8 : noff+10]))
		rdataStart := noff + 10
		rdataEnd := rdataStart + rdlen
		if rdataEnd > len(resp) {
			return nil, fmt.Errorf("truncated rdata")
		}
		answers = append(answers, dnsAnswer{
			Name: name, Type: t, TTL: ttl,
			RDATA: append([]byte{}, resp[rdataStart:rdataEnd]...),
		})
		off = rdataEnd
	}
	return answers, nil
}

func readName(buf []byte, off int) (string, int, error) {
	var parts []string
	jumped := false
	origOff := off
	for {
		if off >= len(buf) {
			return "", 0, fmt.Errorf("name overflow")
		}
		l := int(buf[off])
		if l == 0 {
			off++
			if !jumped {
				return strings.Join(parts, "."), off, nil
			}
			return strings.Join(parts, "."), origOff, nil
		}
		if l&0xC0 == 0xC0 {
			if off+1 >= len(buf) {
				return "", 0, fmt.Errorf("pointer overflow")
			}
			ptr := int(binary.BigEndian.Uint16(buf[off:off+2]) & 0x3FFF)
			if !jumped {
				origOff = off + 2
				jumped = true
			}
			off = ptr
			continue
		}
		off++
		if off+l > len(buf) {
			return "", 0, fmt.Errorf("label overflow")
		}
		parts = append(parts, string(buf[off:off+l]))
		off += l
	}
}

func parseSOA(rdata []byte) map[string]any {
	mname, off, err := readName(rdata, 0)
	if err != nil {
		return nil
	}
	rname, off, err := readName(rdata, off)
	if err != nil {
		return nil
	}
	if off+20 > len(rdata) {
		return nil
	}
	serial := binary.BigEndian.Uint32(rdata[off : off+4])
	refresh := binary.BigEndian.Uint32(rdata[off+4 : off+8])
	retry := binary.BigEndian.Uint32(rdata[off+8 : off+12])
	expire := binary.BigEndian.Uint32(rdata[off+12 : off+16])
	minimum := binary.BigEndian.Uint32(rdata[off+16 : off+20])
	return map[string]any{
		"mname": mname, "rname": rname,
		"serial": serial, "refresh": refresh,
		"retry": retry, "expire": expire, "minimum": minimum,
	}
}

func parseMX(rdata []byte) (uint16, string) {
	if len(rdata) < 3 {
		return 0, ""
	}
	pref := binary.BigEndian.Uint16(rdata[0:2])
	name, _, _ := readName(rdata, 2)
	return pref, name
}

func parseCAA(rdata []byte) map[string]any {
	if len(rdata) < 2 {
		return nil
	}
	flags := rdata[0]
	tagLen := int(rdata[1])
	if 2+tagLen > len(rdata) {
		return nil
	}
	tag := string(rdata[2 : 2+tagLen])
	value := string(rdata[2+tagLen:])
	return map[string]any{"flags": flags, "tag": tag, "value": value}
}

func parseSRV(rdata []byte) map[string]any {
	if len(rdata) < 7 {
		return nil
	}
	priority := binary.BigEndian.Uint16(rdata[0:2])
	weight := binary.BigEndian.Uint16(rdata[2:4])
	port := binary.BigEndian.Uint16(rdata[4:6])
	target, _, _ := readName(rdata, 6)
	return map[string]any{"priority": priority, "weight": weight, "port": port, "target": target}
}

func parseDS(rdata []byte) map[string]any {
	if len(rdata) < 4 {
		return nil
	}
	keyTag := binary.BigEndian.Uint16(rdata[0:2])
	algorithm := rdata[2]
	digestType := rdata[3]
	digest := rdata[4:]
	return map[string]any{
		"key_tag": keyTag, "algorithm": algorithm,
		"digest_type": digestType,
		"digest_len":  len(digest),
	}
}
