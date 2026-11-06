package t32_malshield

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
)

func md5Hex(b []byte) string    { h := md5.Sum(b); return hex.EncodeToString(h[:]) }
func sha1Hex(b []byte) string   { h := sha1.Sum(b); return hex.EncodeToString(h[:]) }
func sha256Hex(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
