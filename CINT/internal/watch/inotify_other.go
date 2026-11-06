//go:build !linux

package watch

import (
	"context"
	"errors"
)

func inotifyWatch(ctx context.Context, root string, cb func(Event)) error {
	return errors.New("inotify only available on linux")
}
