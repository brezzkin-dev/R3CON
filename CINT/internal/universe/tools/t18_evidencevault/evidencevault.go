package t18_evidencevault

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	core "github.com/brezzkin-dev/CINT/internal/universe/core"
)

var vaultLock sync.Mutex

type Entry struct {
	AddedAt    string `json:"added_at"`
	AddedBy    string `json:"added_by"`
	Hostname   string `json:"hostname"`
	Label      string `json:"label,omitempty"`
	SourcePath string `json:"source_path"`
	Size       int64  `json:"size"`
	MTime      string `json:"mtime"`
	SHA256     string `json:"sha256"`
	MD5        string `json:"md5_legacy"`
	BlobPath   string `json:"blob_path"`
	PrevHash   string `json:"prev_hash"`
	ThisHash   string `json:"this_hash"`
}

type Manifest struct {
	Version string  `json:"version"`
	Created string  `json:"created"`
	Entries []Entry `json:"entries"`
}

func Init(vault string) (*core.Result, error) {
	r := core.NewResult("evidencevault-init", vault)
	blobs := filepath.Join(vault, "blobs")
	if err := os.MkdirAll(blobs, 0700); err != nil {
		return r, fmt.Errorf("mkdir blobs: %w", err)
	}
	mfPath := filepath.Join(vault, "manifest.json")
	if _, err := os.Stat(mfPath); err == nil {
		r.Add(core.Finding{Tool: "evidencevault", Severity: core.SevMed,
			Title: "Vault already exists", Detail: mfPath})
		r.Finish()
		return r, nil
	}
	mf := Manifest{Version: "1.1", Created: nowUTC()}
	if err := atomicWriteJSON(mfPath, mf); err != nil {
		return r, err
	}
	chainPath := filepath.Join(vault, "chain.log")
	if err := atomicWriteFile(chainPath, nil); err != nil {
		return r, err
	}
	r.Add(core.Finding{Tool: "evidencevault", Severity: core.SevInfo,
		Title: "Vault initialized", Detail: vault})
	r.AddExtra("manifest", mfPath)
	r.Finish()
	return r, nil
}

func Add(vault, path, label string) (*core.Result, error) {
	r := core.NewResult("evidencevault-add", path)
	vaultLock.Lock()
	defer vaultLock.Unlock()

	mf, err := loadManifest(vault)
	if err != nil {
		return r, err
	}

	stat, err := os.Stat(path)
	if err != nil {
		return r, fmt.Errorf("stat: %w", err)
	}

	sha, md, size, err := hashFile(path)
	if err != nil {
		return r, err
	}
	if size != stat.Size() {
		return r, fmt.Errorf("hash size %d != stat size %d", size, stat.Size())
	}

	blobRel := filepath.Join("blobs", sha)
	blobAbs := filepath.Join(vault, blobRel)
	if _, err := os.Stat(blobAbs); os.IsNotExist(err) {
		if err := copyFile(path, blobAbs); err != nil {
			return r, fmt.Errorf("copy blob: %w", err)
		}
	} else if err != nil {
		return r, fmt.Errorf("stat blob: %w", err)
	}

	prev := "genesis"
	if len(mf.Entries) > 0 {
		prev = mf.Entries[len(mf.Entries)-1].ThisHash
	}

	usr, _ := user.Current()
	who := ""
	if usr != nil {
		who = usr.Username
	}
	host, _ := os.Hostname()

	entry := Entry{
		AddedAt: nowUTC(), AddedBy: who, Hostname: host,
		Label: label, SourcePath: path,
		Size: size, MTime: stat.ModTime().UTC().Format(time.RFC3339),
		SHA256: sha, MD5: md, BlobPath: blobRel, PrevHash: prev,
	}
	entry.ThisHash = chainHash(entry)

	mf.Entries = append(mf.Entries, entry)
	if err := atomicWriteJSON(filepath.Join(vault, "manifest.json"), mf); err != nil {
		return r, fmt.Errorf("write manifest: %w", err)
	}

	line, _ := json.Marshal(entry)
	f, err := os.OpenFile(filepath.Join(vault, "chain.log"),
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return r, fmt.Errorf("open chain.log: %w", err)
	}
	if _, werr := f.Write(append(line, '\n')); werr != nil {
		f.Close()
		return r, fmt.Errorf("append chain.log: %w", werr)
	}
	if serr := f.Sync(); serr != nil {
		f.Close()
		return r, fmt.Errorf("sync chain.log: %w", serr)
	}
	if cerr := f.Close(); cerr != nil {
		return r, fmt.Errorf("close chain.log: %w", cerr)
	}

	r.Add(core.Finding{Tool: "evidencevault", Severity: core.SevInfo,
		Title:    "Evidence added",
		Detail:   fmt.Sprintf("%s → %s", path, sha[:16]),
		Evidence: map[string]any{"sha256": sha, "this_hash": entry.ThisHash}})
	r.AddExtra("entry", entry)
	r.Finish()
	return r, nil
}

func Verify(vault string) (*core.Result, error) {
	r := core.NewResult("evidencevault-verify", vault)
	mf, err := loadManifest(vault)
	if err != nil {
		return r, err
	}

	prev := "genesis"
	broken := 0
	var results []map[string]any
	blobRoot := filepath.Join(vault, "blobs")
	blobRootAbs, _ := filepath.Abs(blobRoot)

	for _, e := range mf.Entries {
		status := "ok"

		canonicalRel := filepath.Join("blobs", e.SHA256)
		canonicalAbs := filepath.Join(vault, canonicalRel)
		absPath, aerr := filepath.Abs(canonicalAbs)
		if aerr != nil || !strings.HasPrefix(absPath, blobRootAbs+string(filepath.Separator)) {
			status = "path_escape"
			broken++
			r.Add(core.Finding{Tool: "evidencevault", Severity: core.SevCrit,
				Title: "Manifest blob path escapes vault", Detail: e.SHA256})
			results = append(results, map[string]any{"sha256": e.SHA256, "status": status})
			continue
		}

		f, oErr := os.Open(absPath)
		if oErr != nil {
			status = "missing_blob"
			broken++
			r.Add(core.Finding{Tool: "evidencevault", Severity: core.SevCrit,
				Title: "Missing blob", Detail: e.SHA256})
			results = append(results, map[string]any{"sha256": e.SHA256, "status": status})
		} else {
			h := sha256.New()
			written, cpErr := io.Copy(h, f)
			closeErr := f.Close()
			if cpErr != nil || closeErr != nil {
				status = "read_error"
				broken++
			} else if written != e.Size {
				status = "size_mismatch"
				broken++
				r.Add(core.Finding{Tool: "evidencevault", Severity: core.SevCrit,
					Title:    "Blob size mismatch",
					Evidence: map[string]any{"expected": e.Size, "got": written}})
			} else if hex.EncodeToString(h.Sum(nil)) != e.SHA256 {
				status = "hash_mismatch"
				broken++
				r.Add(core.Finding{Tool: "evidencevault", Severity: core.SevCrit,
					Title: "Blob hash mismatch (tampered)", Detail: e.SHA256})
			}
			results = append(results, map[string]any{"sha256": e.SHA256, "status": status})
		}

		if e.PrevHash != prev {
			status = "chain_broken"
			broken++
			r.Add(core.Finding{Tool: "evidencevault", Severity: core.SevCrit,
				Title: "Chain broken", Detail: e.SHA256})
		}
		recomputed := chainHash(Entry{
			AddedAt: e.AddedAt, AddedBy: e.AddedBy, Hostname: e.Hostname,
			Label: e.Label, SourcePath: e.SourcePath, Size: e.Size,
			MTime: e.MTime, SHA256: e.SHA256, MD5: e.MD5,
			BlobPath: e.BlobPath, PrevHash: e.PrevHash,
		})
		if recomputed != e.ThisHash {
			status = "chain_hash_mismatch"
			broken++
			r.Add(core.Finding{Tool: "evidencevault", Severity: core.SevCrit,
				Title: "Chain hash mismatch", Detail: e.SHA256})
		}
		prev = e.ThisHash
	}

	r.AddExtra("entries", results)
	r.AddExtra("total", len(mf.Entries))
	r.AddExtra("broken", broken)
	if broken == 0 {
		r.Add(core.Finding{Tool: "evidencevault", Severity: core.SevInfo,
			Title: fmt.Sprintf("Vault clean: %d entries verified", len(mf.Entries))})
	}
	r.Finish()
	return r, nil
}

func List(vault string) (*core.Result, error) {
	r := core.NewResult("evidencevault-list", vault)
	mf, err := loadManifest(vault)
	if err != nil {
		return r, err
	}
	entries := mf.Entries
	sort.Slice(entries, func(i, j int) bool { return entries[i].AddedAt < entries[j].AddedAt })
	r.AddExtra("entries", entries)
	r.AddExtra("count", len(entries))
	r.Add(core.Finding{Tool: "evidencevault", Severity: core.SevInfo,
		Title: fmt.Sprintf("%d entries in vault", len(entries))})
	r.Finish()
	return r, nil
}

func loadManifest(vault string) (*Manifest, error) {
	p := filepath.Join(vault, "manifest.json")
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, fmt.Errorf("read manifest: %w", err)
	}
	var mf Manifest
	if err := json.Unmarshal(b, &mf); err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}
	return &mf, nil
}

func hashFile(p string) (sha, md string, size int64, err error) {
	f, err := os.Open(p)
	if err != nil {
		return "", "", 0, err
	}
	defer f.Close()
	h1 := sha256.New()
	h2 := md5.New()
	n, cpErr := io.Copy(io.MultiWriter(h1, h2), f)
	if cpErr != nil {
		return "", "", 0, cpErr
	}
	return hex.EncodeToString(h1.Sum(nil)), hex.EncodeToString(h2.Sum(nil)), n, nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Sync(); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

func atomicWriteJSON(p string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return atomicWriteFile(p, b)
}

func atomicWriteFile(p string, b []byte) error {
	dir := filepath.Dir(p)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, p)
}

func chainHash(e Entry) string {
	h := sha256.New()
	parts := []string{
		e.AddedAt, e.AddedBy, e.Hostname, e.Label, e.SourcePath,
		fmt.Sprintf("%d", e.Size), e.MTime, e.SHA256, e.MD5,
		e.BlobPath, e.PrevHash,
	}
	for _, p := range parts {
		h.Write([]byte(p))
		h.Write([]byte("\x00"))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func nowUTC() string { return time.Now().UTC().Format(time.RFC3339) }
