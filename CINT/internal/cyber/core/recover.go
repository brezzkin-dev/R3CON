package core

import (
	"fmt"
	"os"
)

func Recover(name string) {
	if r := recover(); r != nil {
		fmt.Fprintf(os.Stderr, "panic in %s: %v\n", name, r)
	}
}

func SafeRun(name string, fn func()) {
	defer Recover(name)
	fn()
}
