package t06_mailtrace

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"net"
	"strings"

	core "github.com/brezzkin-dev/CINT/internal/universe/core"
)

func Run(email string) (*core.Result, error) {
	r := core.NewResult("mailtrace", email)
	email = strings.TrimSpace(strings.ToLower(email))
	at := strings.LastIndex(email, "@")
	if at < 0 {
		return r, fmt.Errorf("invalid email")
	}
	domain := email[at+1:]
	local := email[:at]

	ctx := context.Background()

	if mxs, err := net.LookupMX(domain); err == nil {
		out := make([]map[string]any, len(mxs))
		for i, m := range mxs {
			out[i] = map[string]any{"host": m.Host, "pref": m.Pref}
		}
		r.AddExtra("mx", out)
	}

	if txts, err := net.LookupTXT(domain); err == nil {
		for _, t := range txts {
			if strings.HasPrefix(t, "v=spf1") {
				r.AddExtra("spf", t)
			}
		}
	}
	if dmarcs, err := net.LookupTXT("_dmarc." + domain); err == nil {
		for _, t := range dmarcs {
			if strings.HasPrefix(t, "v=DMARC1") {
				r.AddExtra("dmarc", t)
			}
		}
	}

	gravatar := gravatarURL(local + "@" + domain)
	r.AddExtra("gravatar", gravatar)
	status, _, _, _ := core.HTTPGet(ctx, gravatar+"?d=404", nil)
	if status == 200 {
		r.Add(core.Finding{Tool: "mailtrace", Severity: core.SevInfo,
			Title: "Gravatar exists", Detail: gravatar})
	}

	if err := hibpPasswordRange(ctx, email, r); err != nil {
		core.Debugf("hibp: %v", err)
	}

	r.Finish()
	return r, nil
}

func gravatarURL(email string) string {
	h := md5.Sum([]byte(strings.ToLower(strings.TrimSpace(email))))
	return "https://www.gravatar.com/avatar/" + hex.EncodeToString(h[:])
}

// hibpPasswordRange queries the free k-anonymity range API. Only the
// first 5 hex chars of SHA-1 leave the client. This checks whether the
// email-as-password appears in the corpus, not whether the email was
// breached (that requires a paid HIBP API key).
func hibpPasswordRange(ctx context.Context, email string, r *core.Result) error {
	sha1 := sha1Hex(email)
	if len(sha1) < 5 {
		return nil
	}
	prefix := sha1[:5]
	suffix := sha1[5:]
	url := "https://api.pwnedpasswords.com/range/" + prefix
	status, _, body, err := core.HTTPGet(ctx, url, nil)
	if err != nil || status != 200 {
		return err
	}
	for _, line := range strings.Split(string(body), "\n") {
		parts := strings.SplitN(strings.TrimSpace(line), ":", 2)
		if len(parts) == 2 && strings.EqualFold(parts[0], suffix) {
			r.Add(core.Finding{
				Tool: "mailtrace", Severity: core.SevHigh,
				Title:  "Email as password appears in HIBP",
				Detail: "count: " + parts[1],
			})
			return nil
		}
	}
	r.AddExtra("hibp_password_match", false)
	return nil
}

func sha1Hex(s string) string {
	const (
		h0 uint32 = 0x67452301
		h1 uint32 = 0xEFCDAB89
		h2 uint32 = 0x98BADCFE
		h3 uint32 = 0x10325476
		h4 uint32 = 0xC3D2E1F0
	)
	msg := []byte(s)
	l := uint64(len(msg)) * 8
	msg = append(msg, 0x80)
	for len(msg)%64 != 56 {
		msg = append(msg, 0)
	}
	for i := 7; i >= 0; i-- {
		msg = append(msg, byte(l>>uint(i*8)))
	}
	a, b, c, d, e := h0, h1, h2, h3, h4
	rotl := func(x uint32, n uint) uint32 { return (x << n) | (x >> (32 - n)) }
	for i := 0; i < len(msg); i += 64 {
		var w [80]uint32
		for j := 0; j < 16; j++ {
			w[j] = uint32(msg[i+j*4])<<24 | uint32(msg[i+j*4+1])<<16 | uint32(msg[i+j*4+2])<<8 | uint32(msg[i+j*4+3])
		}
		for j := 16; j < 80; j++ {
			w[j] = rotl(w[j-3]^w[j-8]^w[j-14]^w[j-16], 1)
		}
		aa, bb, cc, dd, ee := a, b, c, d, e
		for j := 0; j < 80; j++ {
			var f, k uint32
			switch {
			case j < 20:
				f = (bb & cc) | (^bb & dd)
				k = 0x5A827999
			case j < 40:
				f = bb ^ cc ^ dd
				k = 0x6ED9EBA1
			case j < 60:
				f = (bb & cc) | (bb & dd) | (cc & dd)
				k = 0x8F1BBCDC
			default:
				f = bb ^ cc ^ dd
				k = 0xCA62C1D6
			}
			tmp := rotl(aa, 5) + f + ee + k + w[j]
			ee = dd
			dd = cc
			cc = rotl(bb, 30)
			bb = aa
			aa = tmp
		}
		a += aa
		b += bb
		c += cc
		d += dd
		e += ee
	}
	out := make([]byte, 20)
	for i, v := range []uint32{a, b, c, d, e} {
		out[i*4] = byte(v >> 24)
		out[i*4+1] = byte(v >> 16)
		out[i*4+2] = byte(v >> 8)
		out[i*4+3] = byte(v)
	}
	return hex.EncodeToString(out)
}
