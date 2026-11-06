package main

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/brezzkin-dev/CINT/internal/bloom"
	"github.com/brezzkin-dev/CINT/internal/carve"
	"github.com/brezzkin-dev/CINT/internal/chunk"
	"github.com/brezzkin-dev/CINT/internal/core"
	"github.com/brezzkin-dev/CINT/internal/entropy"
	"github.com/brezzkin-dev/CINT/internal/hash"
	"github.com/brezzkin-dev/CINT/internal/index"
	"github.com/brezzkin-dev/CINT/internal/magic"
	"github.com/brezzkin-dev/CINT/internal/modules/classify"
	"github.com/brezzkin-dev/CINT/internal/modules/dup"
	"github.com/brezzkin-dev/CINT/internal/modules/hidden"
	"github.com/brezzkin-dev/CINT/internal/modules/recover"
	"github.com/brezzkin-dev/CINT/internal/modules/tree"
	"github.com/brezzkin-dev/CINT/internal/permaudit"
	"github.com/brezzkin-dev/CINT/internal/scan"
	"github.com/brezzkin-dev/CINT/internal/watch"
)

const (
	version = "2.1.0"
	author  = "L1ghtXr"
)

var banner = `
    ____  _   _    _    _   _ _____ _____ ___  ____
   |  _ \| | | |  / \  | \ | |_   _|  ___/ _ \|  _ \
   | |_) | |_| | / _ \ |  \| | | | | |_ | | | | |_) |
   |  __/|  _  |/ ___ \| |\  | | | |  _|| |_| |  _ <
   |_|   |_| |_/_/   \_\_| \_| |_| |_|   \___/|_| \_\
    PHANTOMFS ` + version + ` · author ` + author + ` · ` + runtime.Version() + `
    filesystem intelligence · no AI · no ML
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
		case "scan":
			cmdScan(args)
		case "hidden":
			cmdHidden(args)
		case "dupes":
			cmdDupes(args)
		case "watch":
			cmdWatch(args)
		case "tree":
			cmdTree(args)
		case "classify":
			cmdClassify(args)
		case "recover":
			cmdRecover(args)
		case "snapshot":
			cmdSnapshot(args)
		case "diff":
			cmdDiff(args)
		case "carve":
			cmdCarve(args)
		case "perm":
			cmdPerm(args)
		case "entropy":
			cmdEntropy(args)
		case "dedup":
			cmdDedup(args)
		case "bloom":
			cmdBloom(args)
		case "hash":
			cmdHash(args)
		case "magic":
			cmdMagic(args)
		case "version", "-v", "--version":
			fmt.Printf("phantomfs v%s — author %s\n", version, author)
		case "help", "-h", "--help":
			help()
		case "exit", "quit":
			os.Exit(0)
		default:
			fmt.Fprintf(os.Stderr, "unknown command: %s\n", cmd)
			help()
			os.Exit(2)
		}
	})
}

func help() {
	fmt.Print(banner)
	fmt.Print(`
commands:
  scan        [-root DIR] [-max-depth N] [-min-size B] [-workers N] [-json]
  hidden      [-root DIR] [-json]
  dupes       [-root DIR] [-json]
  watch       [-root DIR] [-mode auto|poll|inotify] [-poll 2s] [-json]
  tree        [-root DIR]
  classify    [-root DIR] [-json]
  recover     [-root DIR]
  snapshot    [-root DIR] [-out file.phfs]
  diff        -old old.phfs -new new.phfs [-json]
  carve       -file disk.img [-out carved/] [-json]
  perm        [-root DIR] [-json]
  entropy     [-root DIR] [-block 4096] [-min 7.0] [-json]
  dedup       [-root DIR] [-min 512] [-avg 4096] [-max 65536] [-json]
  bloom       [-root DIR] [-check-file PATH] [-fp 0.001]
  hash        -file PATH [-json]
  magic       -file PATH [-json]
  version, help
`)
}

func interactive() {
	fmt.Println(banner)
	sc := bufio.NewScanner(os.Stdin)
	for {
		fmt.Print("phantomfs> ")
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

func emitJSON(v any) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshal failed: %v\n", err)
		os.Exit(1)
	}
	os.Stdout.Write(b)
	os.Stdout.Write([]byte("\n"))
}

func cmdScan(args []string) {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	root := fs.String("root", ".", "scan root")
	maxDepth := fs.Int("max-depth", 0, "0 = unlimited")
	minSize := fs.Int64("min-size", 0, "skip smaller files")
	workers := fs.Int("workers", 0, "0 = NumCPU")
	jsonOut := fs.Bool("json", false, "JSON output")
	_ = fs.Parse(args)
	ctx := context.Background()
	entries, err := scan.WalkContext(ctx, scan.Options{
		Root: *root, MaxDepth: *maxDepth, MinSize: *minSize, Workers: *workers,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if *jsonOut {
		emitJSON(entries)
		return
	}
	var dirs, files, total, sparse int64
	for _, e := range entries {
		if e.IsDir {
			dirs++
		} else {
			files++
			total += e.Size
			if e.Sparse {
				sparse++
			}
		}
	}
	fmt.Printf("root:   %s\ndirs:   %d\nfiles:  %d\nbytes:  %d\nsparse: %d\n",
		*root, dirs, files, total, sparse)
}

func cmdHidden(args []string) {
	fs := flag.NewFlagSet("hidden", flag.ExitOnError)
	root := fs.String("root", ".", "scan root")
	jsonOut := fs.Bool("json", false, "JSON output")
	_ = fs.Parse(args)
	entries, err := scan.Walk(scan.Options{Root: *root})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	r := hidden.Detect(entries)
	if *jsonOut {
		emitJSON(r)
		return
	}
	fmt.Printf("dotfiles:   %d\n", len(r.DotFiles))
	fmt.Printf("symlinks:   %d\n", len(r.Symlinks))
	fmt.Printf("unreadable: %d\n", len(r.Unreadable))
	fmt.Printf("deep paths: %d\n", len(r.DeepPaths))
	fmt.Printf("zero-byte:  %d\n", len(r.ZeroByte))
	fmt.Printf("exec files: %d\n", len(r.ExecFiles))
	fmt.Printf("hardlinks:  %d\n", len(r.Hardlinks))
	fmt.Printf("sparse:     %d\n", len(r.Sparse))
}

func cmdDupes(args []string) {
	fs := flag.NewFlagSet("dupes", flag.ExitOnError)
	root := fs.String("root", ".", "scan root")
	jsonOut := fs.Bool("json", false, "JSON output")
	_ = fs.Parse(args)
	entries, err := scan.Walk(scan.Options{Root: *root})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	groups := dup.Find(entries)
	if *jsonOut {
		emitJSON(groups)
		return
	}
	fmt.Printf("duplicate groups: %d\n", len(groups))
	fmt.Printf("reclaimable:      %d bytes\n", dup.ReclaimedBytes(groups))
	for i, g := range groups {
		fmt.Printf("\n[%d] size=%d xxh64=%s\n", i+1, g.Size, g.Hash)
		for _, p := range g.Paths {
			fmt.Printf("    %s\n", p)
		}
	}
}

func cmdWatch(args []string) {
	fs := flag.NewFlagSet("watch", flag.ExitOnError)
	root := fs.String("root", ".", "watch root")
	mode := fs.String("mode", "auto", "auto|poll|inotify")
	poll := fs.Duration("poll", 2*time.Second, "polling interval")
	jsonOut := fs.Bool("json", false, "JSON lines")
	_ = fs.Parse(args)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	cb := func(ev watch.Event) {
		if *jsonOut {
			b, _ := json.Marshal(map[string]string{"kind": ev.Kind, "path": ev.Path})
			fmt.Println(string(b))
		} else {
			fmt.Printf("%s %-10s %s\n", time.Now().Format("15:04:05"), ev.Kind, ev.Path)
		}
	}
	if err := watch.Watch(ctx, *root, *mode, *poll, cb); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func cmdTree(args []string) {
	fs := flag.NewFlagSet("tree", flag.ExitOnError)
	root := fs.String("root", ".", "root")
	_ = fs.Parse(args)
	entries, err := scan.Walk(scan.Options{Root: *root})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	n := tree.Build(entries)
	fmt.Println(*root)
	tree.Render(n, "", os.Stdout)
}

func cmdClassify(args []string) {
	fs := flag.NewFlagSet("classify", flag.ExitOnError)
	root := fs.String("root", ".", "root")
	jsonOut := fs.Bool("json", false, "JSON output")
	_ = fs.Parse(args)
	entries, err := scan.Walk(scan.Options{Root: *root})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	results := classify.Classify(entries, nil)
	if *jsonOut {
		emitJSON(results)
		return
	}
	counts := map[string]int{}
	sevCounts := map[string]int{}
	for _, r := range results {
		counts[r.Category]++
		sevCounts[r.Severity]++
	}
	fmt.Printf("classified %d files\n", len(results))
	for k, v := range counts {
		fmt.Printf("  %-24s %d\n", k, v)
	}
	fmt.Printf("\nseverity:\n")
	for k, v := range sevCounts {
		fmt.Printf("  %-10s %d\n", k, v)
	}
}

func cmdRecover(args []string) {
	fs := flag.NewFlagSet("recover", flag.ExitOnError)
	root := fs.String("root", ".", "root")
	_ = fs.Parse(args)
	n, err := recover.Reconstruct(*root)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("reconstructed %d dirs under %s\n", n, *root)
}

func cmdSnapshot(args []string) {
	fs := flag.NewFlagSet("snapshot", flag.ExitOnError)
	root := fs.String("root", ".", "root")
	out := fs.String("out", "snapshot.phfs", "output file")
	_ = fs.Parse(args)
	entries, err := scan.Walk(scan.Options{Root: *root})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := index.Save(*out, entries); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("snapshot saved: %s (%d entries)\n", *out, len(entries))
}

func cmdDiff(args []string) {
	fs := flag.NewFlagSet("diff", flag.ExitOnError)
	oldP := fs.String("old", "", "old snapshot")
	newP := fs.String("new", "", "new snapshot")
	jsonOut := fs.Bool("json", false, "JSON output")
	_ = fs.Parse(args)
	if *oldP == "" || *newP == "" {
		fmt.Fprintln(os.Stderr, "diff: -old and -new required")
		os.Exit(2)
	}
	oldE, err := index.Load(*oldP)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load old: %v\n", err)
		os.Exit(1)
	}
	newE, err := index.Load(*newP)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load new: %v\n", err)
		os.Exit(1)
	}
	changes := index.Diff(oldE, newE)
	if *jsonOut {
		emitJSON(changes)
		return
	}
	fmt.Printf("changes: %d\n", len(changes))
	for _, c := range changes {
		fmt.Printf("  %-10s %s\n", c.Kind, c.Path)
	}
}

func cmdCarve(args []string) {
	fs := flag.NewFlagSet("carve", flag.ExitOnError)
	file := fs.String("file", "", "input file")
	out := fs.String("out", "carved", "output dir")
	jsonOut := fs.Bool("json", false, "JSON output")
	_ = fs.Parse(args)
	if *file == "" {
		fmt.Fprintln(os.Stderr, "carve: -file required")
		os.Exit(2)
	}
	carved, err := carve.CarveFile(*file, *out)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if *jsonOut {
		emitJSON(carved)
		return
	}
	fmt.Printf("carved %d files into %s\n", len(carved), *out)
	for _, c := range carved {
		fmt.Printf("  %-6s offset=%d size=%d -> %s\n", c.Type, c.Offset, c.Size, c.Path)
	}
}

func cmdPerm(args []string) {
	fs := flag.NewFlagSet("perm", flag.ExitOnError)
	root := fs.String("root", ".", "root")
	jsonOut := fs.Bool("json", false, "JSON output")
	_ = fs.Parse(args)
	entries, err := scan.Walk(scan.Options{Root: *root})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	findings := permaudit.Audit(entries)
	if *jsonOut {
		emitJSON(findings)
		return
	}
	fmt.Printf("perm findings: %d\n", len(findings))
	for _, f := range findings {
		fmt.Printf("  %-16s %-12s %s\n", f.Issue, f.Mode, f.Path)
	}
}

func cmdEntropy(args []string) {
	fs := flag.NewFlagSet("entropy", flag.ExitOnError)
	root := fs.String("root", ".", "root")
	block := fs.Int("block", 4096, "block size")
	minE := fs.Float64("min", 7.0, "report files with max block entropy >= value")
	jsonOut := fs.Bool("json", false, "JSON output")
	_ = fs.Parse(args)
	entries, err := scan.Walk(scan.Options{Root: *root})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	type result struct {
		Path      string  `json:"path"`
		Size      int64   `json:"size"`
		MaxBlock  float64 `json:"max_block"`
		BlockIdx  int     `json:"block_idx"`
		Detection string  `json:"detection,omitempty"`
	}
	var results []result
	for _, e := range entries {
		if e.IsDir || !e.Readable || e.Size < int64(*block) {
			continue
		}
		data, err := os.ReadFile(e.Path)
		if err != nil {
			continue
		}
		maxEn, blk := entropy.BlockMax(data, *block)
		if maxEn < *minE {
			continue
		}
		res := result{Path: e.Path, Size: e.Size, MaxBlock: maxEn, BlockIdx: blk}
		if len(data) >= 512 {
			if mime, desc, ok := magic.Detect(data[:512]); ok {
				res.Detection = mime + " (" + desc + ")"
			}
		}
		results = append(results, res)
	}
	if *jsonOut {
		emitJSON(results)
		return
	}
	fmt.Printf("high-entropy files (>=%.2f): %d\n", *minE, len(results))
	for _, r := range results {
		fmt.Printf("  %.4f blk=%d size=%d %s\n", r.MaxBlock, r.BlockIdx, r.Size, r.Path)
	}
}

func cmdDedup(args []string) {
	fs := flag.NewFlagSet("dedup", flag.ExitOnError)
	root := fs.String("root", ".", "root")
	minSize := fs.Int("min", 512, "min chunk size")
	avgSize := fs.Int("avg", 4096, "avg chunk size (bytes)")
	maxSize := fs.Int("max", 65536, "max chunk size")
	jsonOut := fs.Bool("json", false, "JSON output")
	_ = fs.Parse(args)
	entries, err := scan.Walk(scan.Options{Root: *root})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	f := chunk.NewFastCDC(*minSize, *avgSize, *maxSize, 42)
	chunkHashes := map[uint64]int{}
	var totalBytes, totalChunks int64
	var fileCount int

	for _, e := range entries {
		if e.IsDir || !e.Readable {
			continue
		}
		data, err := os.ReadFile(e.Path)
		if err != nil {
			continue
		}
		fileCount++
		cuts := f.Cut(data)
		prev := 0
		for _, c := range cuts {
			if c <= prev {
				continue
			}
			slice := data[prev:c]
			h := hash.XXHash64(slice, 0)
			chunkHashes[h]++
			totalBytes += int64(len(slice))
			totalChunks++
			prev = c
		}
	}

	var uniqueChunks, dupChunks, dupBytes int64
	for _, count := range chunkHashes {
		if count == 1 {
			uniqueChunks++
		} else {
			dupChunks += int64(count - 1)
		}
	}
	if totalChunks > 0 {
		avg := totalBytes / totalChunks
		dupBytes = avg * dupChunks
	}

	summary := map[string]any{
		"files":            fileCount,
		"total_chunks":     totalChunks,
		"unique_chunks":    uniqueChunks,
		"duplicate_chunks": dupChunks,
		"total_bytes":      totalBytes,
		"dedup_bytes_est":  dupBytes,
	}
	if *jsonOut {
		emitJSON(summary)
		return
	}
	fmt.Printf("files:            %d\n", fileCount)
	fmt.Printf("total chunks:     %d\n", totalChunks)
	fmt.Printf("unique chunks:    %d\n", uniqueChunks)
	fmt.Printf("duplicate chunks: %d\n", dupChunks)
	fmt.Printf("total bytes:      %d\n", totalBytes)
	fmt.Printf("dedup bytes est:  %d\n", dupBytes)
}

func cmdBloom(args []string) {
	fs := flag.NewFlagSet("bloom", flag.ExitOnError)
	root := fs.String("root", ".", "root")
	checkFile := fs.String("check-file", "", "file to test")
	checkHash := fs.String("check-hash", "", "hex xxhash64 to test")
	fpRate := fs.Float64("fp", 0.001, "target false-positive rate")
	jsonOut := fs.Bool("json", false, "JSON output")
	_ = fs.Parse(args)
	entries, err := scan.Walk(scan.Options{Root: *root})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	ctx := context.Background()
	var candidates []core.FileEntry
	for _, e := range entries {
		if !e.IsDir && e.Readable {
			candidates = append(candidates, e)
		}
	}
	hashes := hash.HashParallel(ctx, candidates)
	f := bloom.New(uint64(len(hashes)), *fpRate)
	for _, h := range hashes {
		f.Add(h, h>>32)
	}
	result := map[string]any{
		"entries":  len(hashes),
		"bit_size": f.Size(),
		"k":        f.K(),
	}
	if *checkFile != "" {
		h, err := hash.HashFileXXH64(*checkFile)
		if err == nil {
			result["check_hash"] = fmt.Sprintf("%016x", h)
			result["present"] = f.Contains(h, h>>32)
		}
	}
	if *checkHash != "" {
		b, err := hex.DecodeString(strings.TrimPrefix(*checkHash, "0x"))
		if err == nil && len(b) == 8 {
			var h uint64
			for _, c := range b {
				h = (h << 8) | uint64(c)
			}
			result["check_hash_parsed"] = h
			result["present"] = f.Contains(h, h>>32)
		}
	}
	if *jsonOut {
		emitJSON(result)
		return
	}
	fmt.Printf("entries:  %d\n", result["entries"])
	fmt.Printf("bit size: %d\n", result["bit_size"])
	fmt.Printf("k:        %d\n", result["k"])
	if v, ok := result["present"]; ok {
		fmt.Printf("present:  %v\n", v)
	}
}

func cmdHash(args []string) {
	fs := flag.NewFlagSet("hash", flag.ExitOnError)
	file := fs.String("file", "", "file to hash")
	jsonOut := fs.Bool("json", false, "JSON output")
	_ = fs.Parse(args)
	if *file == "" {
		fmt.Fprintln(os.Stderr, "hash: -file required")
		os.Exit(2)
	}
	h, err := hash.HashFileXXH64(*file)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	out := map[string]string{"file": *file, "xxh64": fmt.Sprintf("%016x", h)}
	if *jsonOut {
		emitJSON(out)
		return
	}
	fmt.Printf("xxh64 %016x  %s\n", h, *file)
}

func cmdMagic(args []string) {
	fs := flag.NewFlagSet("magic", flag.ExitOnError)
	file := fs.String("file", "", "file to identify")
	jsonOut := fs.Bool("json", false, "JSON output")
	_ = fs.Parse(args)
	if *file == "" {
		fmt.Fprintln(os.Stderr, "magic: -file required")
		os.Exit(2)
	}
	f, err := os.Open(*file)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer f.Close()
	head := make([]byte, 512)
	n, _ := f.Read(head)
	mime, desc, ok := magic.Detect(head[:n])
	out := map[string]any{"file": *file, "size": n, "matched": ok, "mime": mime, "desc": desc}
	if *jsonOut {
		emitJSON(out)
		return
	}
	if !ok {
		fmt.Printf("%s: unknown (%d bytes read)\n", *file, n)
		return
	}
	fmt.Printf("%s: %s (%s)\n", *file, mime, desc)
}
