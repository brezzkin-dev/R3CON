package t05_userfinder

import "testing"

func TestStatusBased(t *testing.T) {
	f := statusBased()
	cases := []struct {
		code int
		want Status
	}{
		{200, StatusConfirmed},
		{404, StatusNotFound},
		{401, StatusBlocked},
		{403, StatusBlocked},
		{429, StatusBlocked},
		{302, StatusUnknown},
		{500, StatusUnknown},
	}
	for _, c := range cases {
		got, _ := f(c.code, nil)
		if got != c.want {
			t.Fatalf("code %d: got %s, want %s", c.code, got, c.want)
		}
	}
}

func TestIsSafeUsername(t *testing.T) {
	good := []string{"alice", "bob_99", "x.y", "a-b-c"}
	bad := []string{"", "a/b", "a b", "a@b", "a\nb", string(make([]byte, 65))}
	for _, g := range good {
		if !isSafeUsername(g) {
			t.Fatalf("expected ok: %q", g)
		}
	}
	for _, b := range bad {
		if isSafeUsername(b) {
			t.Fatalf("expected reject: %q", b)
		}
	}
}
