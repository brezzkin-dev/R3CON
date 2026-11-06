package t09_linktrace

import (
	"net"
	"net/url"
	"testing"
)

func TestAssertSafeURLBlocks(t *testing.T) {
	cases := []string{
		"http://127.0.0.1/",
		"http://localhost/",
		"http://169.254.169.254/latest/meta-data/",
		"http://10.0.0.1/",
		"http://192.168.1.1/",
		"ftp://example.com/",
		"http://user:pass@example.com/",
	}
	for _, c := range cases {
		u, err := url.Parse(c)
		if err != nil {
			t.Fatalf("parse %s: %v", c, err)
		}
		if err := assertSafeURL(u); err == nil {
			t.Fatalf("expected block for %s", c)
		}
	}
}

func TestIsBlockedIP(t *testing.T) {
	blocked := []string{
		"127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.0.1",
		"169.254.169.254", "::1", "fe80::1", "0.0.0.0", "::",
	}
	for _, s := range blocked {
		if !isBlockedIP(net.ParseIP(s)) {
			t.Fatalf("%s should be blocked", s)
		}
	}
	allowed := []string{"1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"}
	for _, s := range allowed {
		if isBlockedIP(net.ParseIP(s)) {
			t.Fatalf("%s should not be blocked", s)
		}
	}
}
