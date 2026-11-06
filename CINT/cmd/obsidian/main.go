package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/brezzkin-dev/CINT/internal/cyber/asm"
	"github.com/brezzkin-dev/CINT/internal/cyber/core"
	"github.com/brezzkin-dev/CINT/internal/cyber/cryptan"
	"github.com/brezzkin-dev/CINT/internal/cyber/dfir"
	"github.com/brezzkin-dev/CINT/internal/cyber/intel"
	"github.com/brezzkin-dev/CINT/internal/cyber/malscope"
	"github.com/brezzkin-dev/CINT/internal/cyber/pcap"
	"github.com/brezzkin-dev/CINT/internal/cyber/phish"
	"github.com/brezzkin-dev/CINT/internal/cyber/sysaudit"
	"github.com/brezzkin-dev/CINT/internal/cyber/vulnintel"
	"github.com/brezzkin-dev/CINT/internal/cyber/wsa"
)

const (
	version = "2.1.0"
	author  = "L1ghtXr"
)

var banner = `
   ____  ____   _____ _____ ____ _____   _   _
  / __ \|  _ \ / ____|_   _|  _ \_   _| | \ | |
 | |  | | |_) | (___   | | | |_) || |   |  \| |
 | |  | |  _ < \___ \  | | |  _ < | |   | . ' |
 | |__| | |_) |____) |_| |_| |_) || |   | |\  |
  \____/|____/|_____/|_____|____/ |_|   |_| \_|
  OBSIDIAN ` + version + ` · author ` + author + ` · ` + runtime.Version() + `
  10 cyber tools · no AI · no ML
`

func main() {
	if len(os.Args) < 2 {
		interactive()
		return
	}
	dispatch(os.Args[1], os.Args[2:])
}

func dispatch(cmd string, args []string) {
	core.SafeRun(cmd, func() {
		switch cmd {
		case "intel":
			cmdIntel(args)
		case "malscope":
			cmdMalscope(args)
		case "dfir":
			cmdDFIR(args)
		case "asm":
			cmdASM(args)
		case "wsa":
			cmdWSA(args)
		case "pcap":
			cmdPCAP(args)
		case "cryptan":
			cmdCryptan(args)
		case "sysaudit":
			cmdSysaudit(args)
		case "phish":
			cmdPhish(args)
		case "vulnintel":
			cmdVulnIntel(args)
		case "version", "-v", "--version":
			fmt.Printf("obsidian v%s — author %s\n", version, author)
		case "help", "-h", "--help":
			help()
		case "exit", "quit":
			os.Exit(0)
		default:
			fmt.Fprintf(os.Stderr, "unknown: %s\n", cmd)
			help()
			os.Exit(2)
		}
	})
}

func help() {
	fmt.Print(banner)
	fmt.Printf(`
author: %s
usage: obsidian <tool> [flags]

tools:
  intel        [-file iocs.txt | -ioc ip,domain,hash] [-out report.json]
  malscope     -file sample.bin [-yara custom.yara] [-out report.json]
  dfir         [-root /] [-out report.json]
  asm          -domain example.com [-full-ports] [-out report.json]
  wsa          -url https://target [-inject] [-takeover] [-out report.json]
  pcap         -file capture.pcap [-out report.json]
  cryptan      {id|crack|jwt|encrypt|decrypt|freq} [flags]
  sysaudit     [-root /] [-out report.json]
  phish        -url https://suspicious.tld/path [-out report.json]
  vulnintel    {cve|packages} [flags]
  version, help

`, author)
}

func interactive() {
	fmt.Println(banner)
	sc := bufio.NewScanner(os.Stdin)
	for {
		fmt.Print("obsidian> ")
		if !sc.Scan() {
			return
		}
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		dispatch(parts[0], parts[1:])
	}
}

func emit(r *core.Result, out string) {
	r.Finish()
	if out != "" {
		if err := r.SaveJSON(out); err != nil {
			fmt.Fprintf(os.Stderr, "save failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "saved: %s\n", out)
	}
	b, err := json.MarshalIndent(map[string]any{
		"tool": r.Tool, "target": r.Target, "author": author,
		"summary": r.Summary(), "findings": r.Findings, "extra": r.Extra,
	}, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshal failed: %v\n", err)
		os.Exit(1)
	}
	os.Stdout.Write(b)
	os.Stdout.Write([]byte("\n"))
}

func cmdIntel(args []string) {
	fs := flag.NewFlagSet("intel", flag.ExitOnError)
	file := fs.String("file", "", "IOC file")
	ioc := fs.String("ioc", "", "comma-separated")
	out := fs.String("out", "", "JSON report")
	_ = fs.Parse(args)
	var iocs []string
	if *file != "" {
		b, err := os.ReadFile(*file)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		for _, l := range strings.Split(string(b), "\n") {
			if l = strings.TrimSpace(l); l != "" {
				iocs = append(iocs, l)
			}
		}
	}
	if *ioc != "" {
		for _, s := range strings.Split(*ioc, ",") {
			if s = strings.TrimSpace(s); s != "" {
				iocs = append(iocs, s)
			}
		}
	}
	if len(iocs) == 0 {
		fmt.Fprintln(os.Stderr, "intel: -file or -ioc required")
		os.Exit(2)
	}
	emit(intel.Enrich(context.Background(), iocs), *out)
}

func cmdMalscope(args []string) {
	fs := flag.NewFlagSet("malscope", flag.ExitOnError)
	file := fs.String("file", "", "binary")
	yaraPath := fs.String("yara", "", "custom YARA-lite rules file")
	out := fs.String("out", "", "JSON report")
	_ = fs.Parse(args)
	if *file == "" {
		fmt.Fprintln(os.Stderr, "malscope: -file required")
		os.Exit(2)
	}
	r, err := malscope.Analyze(*file, *yaraPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	emit(r, *out)
}

func cmdDFIR(args []string) {
	fs := flag.NewFlagSet("dfir", flag.ExitOnError)
	root := fs.String("root", "/", "root")
	out := fs.String("out", "", "JSON report")
	_ = fs.Parse(args)
	r, err := dfir.Investigate(*root)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	emit(r, *out)
}

func cmdASM(args []string) {
	fs := flag.NewFlagSet("asm", flag.ExitOnError)
	domain := fs.String("domain", "", "apex domain")
	full := fs.Bool("full-ports", false, "scan 1-65535 (slow)")
	out := fs.String("out", "", "JSON report")
	_ = fs.Parse(args)
	if *domain == "" {
		fmt.Fprintln(os.Stderr, "asm: -domain required")
		os.Exit(2)
	}
	emit(asm.Map(context.Background(), *domain, *full), *out)
}

func cmdWSA(args []string) {
	fs := flag.NewFlagSet("wsa", flag.ExitOnError)
	url := fs.String("url", "", "URL")
	inject := fs.Bool("inject", false, "run injection probes")
	takeover := fs.Bool("takeover", false, "subdomain takeover check")
	out := fs.String("out", "", "JSON report")
	_ = fs.Parse(args)
	if *url == "" {
		fmt.Fprintln(os.Stderr, "wsa: -url required")
		os.Exit(2)
	}
	emit(wsa.Audit(context.Background(), *url, wsa.Options{Inject: *inject, Takeover: *takeover}), *out)
}

func cmdPCAP(args []string) {
	fs := flag.NewFlagSet("pcap", flag.ExitOnError)
	file := fs.String("file", "", "pcap")
	out := fs.String("out", "", "JSON report")
	_ = fs.Parse(args)
	if *file == "" {
		fmt.Fprintln(os.Stderr, "pcap: -file required")
		os.Exit(2)
	}
	r, err := pcap.Analyze(*file)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	emit(r, *out)
}

func cmdCryptan(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "cryptan: {id|crack|jwt|encrypt|decrypt|freq|xor|vig|rsa|ecb}")
		os.Exit(2)
	}
	sub, rest := args[0], args[1:]
	fs := flag.NewFlagSet("cryptan-"+sub, flag.ExitOnError)
	out := fs.String("out", "", "output")
	switch sub {
	case "id":
		h := fs.String("hash", "", "hash")
		_ = fs.Parse(rest)
		emit(cryptan.IDResult(*h), *out)
	case "crack":
		h := fs.String("hash", "", "hash")
		wl := fs.String("wordlist", "/usr/share/wordlists/rockyou.txt", "wordlist")
		_ = fs.Parse(rest)
		emit(cryptan.Crack(*h, *wl), *out)
	case "jwt":
		tok := fs.String("token", "", "JWT")
		_ = fs.Parse(rest)
		emit(cryptan.DecodeJWT(*tok), *out)
	case "encrypt", "decrypt":
		key := fs.String("key", "", "hex AES key")
		in := fs.String("in", "", "in file")
		outFile := fs.String("out", "", "out file")
		_ = fs.Parse(rest)
		if err := cryptan.AESCrypt(sub == "encrypt", *key, *in, *outFile); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Printf("%s OK: %s -> %s\n", sub, *in, *outFile)
	case "freq":
		in := fs.String("in", "", "text or file")
		_ = fs.Parse(rest)
		text := *in
		if b, err := os.ReadFile(*in); err == nil {
			text = string(b)
		}
		emit(cryptan.FreqAnalysis(text), "")
	case "xor":
		in := fs.String("in", "", "ciphertext")
		_ = fs.Parse(rest)
		b, err := os.ReadFile(*in)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		emit(cryptan.BreakXOR(b), *out)
	case "vig":
		in := fs.String("in", "", "ciphertext")
		_ = fs.Parse(rest)
		b, err := os.ReadFile(*in)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		emit(cryptan.BreakVigenere(string(b)), *out)
	case "rsa":
		n := fs.String("n", "", "modulus")
		e := fs.String("e", "65537", "exponent")
		_ = fs.Parse(rest)
		emit(cryptan.RSAWeak(*n, *e), *out)
	case "ecb":
		in := fs.String("in", "", "ciphertext file")
		_ = fs.Parse(rest)
		b, err := os.ReadFile(*in)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		emit(cryptan.DetectECB(b), *out)
	}
}

func cmdSysaudit(args []string) {
	fs := flag.NewFlagSet("sysaudit", flag.ExitOnError)
	root := fs.String("root", "/", "root")
	out := fs.String("out", "", "JSON report")
	_ = fs.Parse(args)
	emit(sysaudit.Audit(*root), *out)
}

func cmdPhish(args []string) {
	fs := flag.NewFlagSet("phish", flag.ExitOnError)
	u := fs.String("url", "", "URL")
	out := fs.String("out", "", "JSON report")
	_ = fs.Parse(args)
	if *u == "" {
		fmt.Fprintln(os.Stderr, "phish: -url required")
		os.Exit(2)
	}
	emit(phish.Analyze(context.Background(), *u), *out)
}

func cmdVulnIntel(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "vulnintel: {cve|packages}")
		os.Exit(2)
	}
	sub, rest := args[0], args[1:]
	fs := flag.NewFlagSet("vulnintel-"+sub, flag.ExitOnError)
	out := fs.String("out", "", "output")
	switch sub {
	case "cve":
		id := fs.String("id", "", "CVE ID")
		_ = fs.Parse(rest)
		emit(vulnintel.LookupCVE(context.Background(), *id), *out)
	case "packages":
		_ = fs.Parse(rest)
		emit(vulnintel.ScanPackages(context.Background()), *out)
	}
}
