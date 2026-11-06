package hash

import (
	"context"
	"runtime"
	"sync"

	"github.com/brezzkin-dev/CINT/internal/core"
)

func HashParallel(ctx context.Context, entries []core.FileEntry) map[string]uint64 {
	type job struct {
		path string
	}
	out := make(map[string]uint64, len(entries))
	var mu sync.Mutex

	workers := runtime.NumCPU()
	if workers < 2 {
		workers = 2
	}
	jobs := make(chan job, workers*4)
	var wg sync.WaitGroup

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				h, err := HashFileXXH64(j.path)
				if err != nil {
					core.Debugf("hash %s: %v", j.path, err)
					continue
				}
				mu.Lock()
				out[j.path] = h
				mu.Unlock()
			}
		}()
	}

	for _, e := range entries {
		if e.IsDir || !e.Readable {
			continue
		}
		select {
		case jobs <- job{path: e.Path}:
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return out
		}
	}
	close(jobs)
	wg.Wait()
	return out
}
