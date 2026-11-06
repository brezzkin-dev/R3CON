//go:build !linux && !darwin

package core

import "os"

func ExtInfoOf(info os.FileInfo) ExtInfo { return ExtInfo{} }
