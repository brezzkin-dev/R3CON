package core

import (
	"net"
	"regexp"
	"strings"
)

type IOCType string

const (
	IOCIPv4    IOCType = "ipv4"
	IOCIPv6    IOCType = "ipv6"
	IOCDomain  IOCType = "domain"
	IOCURL     IOCType = "url"
	IOCMD5     IOCType = "md5"
	IOCSHA1    IOCType = "sha1"
	IOCSHA256  IOCType = "sha256"
	IOCEmail   IOCType = "email"
	IOCUnknown IOCType = "unknown"
)

var (
	reMD5    = regexp.MustCompile(`^[a-fA-F0-9]{32}$`)
	reSHA1   = regexp.MustCompile(`^[a-fA-F0-9]{40}$`)
	reSHA256 = regexp.MustCompile(`^[a-fA-F0-9]{64}$`)
	reDomain = regexp.MustCompile(`^(?i)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$`)
	reEmail  = regexp.MustCompile(`(?i)^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$`)
)

func Classify(s string) IOCType {
	s = strings.TrimSpace(s)
	if s == "" {
		return IOCUnknown
	}
	lower := strings.ToLower(s)
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		return IOCURL
	}
	if ip := net.ParseIP(s); ip != nil {
		if ip.To4() != nil {
			return IOCIPv4
		}
		return IOCIPv6
	}
	if reMD5.MatchString(s) {
		return IOCMD5
	}
	if reSHA1.MatchString(s) {
		return IOCSHA1
	}
	if reSHA256.MatchString(s) {
		return IOCSHA256
	}
	if reEmail.MatchString(s) {
		return IOCEmail
	}
	if reDomain.MatchString(s) {
		return IOCDomain
	}
	return IOCUnknown
}