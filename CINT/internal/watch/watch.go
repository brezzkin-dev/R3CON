package watch

import (
	"context"
	"time"

	"github.com/brezzkin-dev/CINT/internal/core"
	"github.com/brezzkin-dev/CINT/internal/scan"
)

type Event struct {
	Kind string
	Path string
}

func Watch(ctx context.Context, root, mode string, poll time.Duration, cb func(Event)) error {
	if mode == "auto" || mode == "inotify" {
		if err := inotifyWatch(ctx, root, cb); err == nil {
			<-ctx.Done()
			return nil
		} else if mode == "inotify" {
			return err
		}
	}
	return pollWatch(ctx, root, poll, cb)
}

func pollWatch(ctx context.Context, root string, poll time.Duration, cb func(Event)) error {
	prev := snapshot(root)
	ticker := time.NewTicker(poll)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			cur := snapshot(root)
			for k, v := range cur {
				old, ok := prev[k]
				if !ok {
					cb(Event{Kind: "created", Path: k})
				} else if old.Size != v.Size || !old.ModTime.Equal(v.ModTime) {
					cb(Event{Kind: "modified", Path: k})
				}
			}
			for k := range prev {
				if _, ok := cur[k]; !ok {
					cb(Event{Kind: "deleted", Path: k})
				}
			}
			prev = cur
		}
	}
}

func snapshot(root string) map[string]core.FileEntry {
	entries, err := scan.Walk(scan.Options{Root: root})
	if err != nil {
		core.Warnf("snapshot: %v", err)
	}
	m := make(map[string]core.FileEntry, len(entries))
	for _, e := range entries {
		m[e.RelPath] = e
	}
	return m
}
