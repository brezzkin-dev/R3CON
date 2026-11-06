package cryptan

import (
	"math/big"
	"strings"

	core "github.com/brezzkin-dev/CINT/internal/cyber/core"
)

func RSAWeak(nStr, eStr string) *core.Result {
	r := core.NewResult("cryptan-rsa", "n="+nStr)

	n := parseBig(nStr)
	if n == nil {
		r.Add(core.Finding{Tool: "cryptan", Severity: core.SevHigh, Title: "invalid modulus"})
		r.Finish()
		return r
	}
	e := parseBig(eStr)
	if e == nil {
		e = big.NewInt(65537)
	}
	r.AddExtra("n_bits", n.BitLen())

	factors := smallFactor(n, 1000000)
	if len(factors) > 0 {
		r.Add(core.Finding{
			Tool: "cryptan", Severity: core.SevCrit,
			Title:    "RSA factorable by small primes",
			Detail:   "factors: " + joinBigs(factors),
			Evidence: map[string]any{"factors": joinBigs(factors)},
		})
		r.Finish()
		return r
	}

	if p, q := fermat(n); p != nil {
		r.Add(core.Finding{
			Tool: "cryptan", Severity: core.SevCrit,
			Title:    "RSA factorable by Fermat (p, q close)",
			Detail:   "p=" + p.String() + " q=" + q.String(),
			Evidence: map[string]any{"p": p.String(), "q": q.String()},
		})
		r.Finish()
		return r
	}

	if d := wiener(n, e); d != nil {
		r.Add(core.Finding{
			Tool: "cryptan", Severity: core.SevCrit,
			Title:    "RSA broken by Wiener's attack (small d)",
			Detail:   "d=" + d.String(),
			Evidence: map[string]any{"d": d.String()},
		})
		r.Finish()
		return r
	}

	r.Add(core.Finding{Tool: "cryptan", Severity: core.SevInfo,
		Title:  "no weak-factor found in quick scan",
		Detail: "n not factorable by small primes, Fermat, or Wiener"})
	r.Finish()
	return r
}

func parseBig(s string) *big.Int {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		v, ok := new(big.Int).SetString(s[2:], 16)
		if !ok {
			return nil
		}
		return v
	}
	if v, ok := new(big.Int).SetString(s, 10); ok {
		return v
	}
	return nil
}

func smallFactor(n *big.Int, limit int) []*big.Int {
	var factors []*big.Int
	rem := new(big.Int).Set(n)
	zero := big.NewInt(0)
	two := big.NewInt(2)
	for new(big.Int).And(rem, big.NewInt(1)).Cmp(zero) == 0 {
		factors = append(factors, two)
		rem.Div(rem, two)
	}
	for p := 3; p < limit; p += 2 {
		pr := big.NewInt(int64(p))
		for new(big.Int).Mod(rem, pr).Cmp(zero) == 0 {
			factors = append(factors, big.NewInt(int64(p)))
			rem.Div(rem, pr)
			if len(factors) >= 8 {
				return factors
			}
		}
	}
	if len(factors) > 0 && rem.Cmp(big.NewInt(1)) > 0 {
		factors = append(factors, new(big.Int).Set(rem))
	}
	return factors
}

func fermat(n *big.Int) (*big.Int, *big.Int) {
	a := new(big.Int).Sqrt(n)
	if new(big.Int).Mul(a, a).Cmp(n) < 0 {
		a.Add(a, big.NewInt(1))
	}
	one := big.NewInt(1)
	for i := 0; i < 100000; i++ {
		a2 := new(big.Int).Mul(a, a)
		b2 := new(big.Int).Sub(a2, n)
		if b2.Sign() < 0 {
			a.Add(a, one)
			continue
		}
		b := new(big.Int).Sqrt(b2)
		if new(big.Int).Mul(b, b).Cmp(b2) == 0 {
			p := new(big.Int).Sub(a, b)
			q := new(big.Int).Add(a, b)
			if p.Cmp(one) > 0 && q.Cmp(one) > 0 &&
				new(big.Int).Mul(p, q).Cmp(n) == 0 {
				return p, q
			}
		}
		a.Add(a, one)
	}
	return nil, nil
}

func wiener(n, e *big.Int) *big.Int {
	frac := continuedFraction(e, n)
	convergents := convergentsOf(e, n, len(frac))
	for _, kd := range convergents {
		k, d := kd[0], kd[1]
		if k.Sign() == 0 {
			continue
		}
		ed1 := new(big.Int).Mul(e, d)
		ed1.Sub(ed1, big.NewInt(1))
		if new(big.Int).Mod(ed1, k).Sign() != 0 {
			continue
		}
		phi := new(big.Int).Div(ed1, k)
		s := new(big.Int).Sub(n, phi)
		s.Add(s, big.NewInt(1))
		s2 := new(big.Int).Mul(s, s)
		fourN := new(big.Int).Lsh(n, 2)
		disc := new(big.Int).Sub(s2, fourN)
		if disc.Sign() < 0 {
			continue
		}
		sqrtD := new(big.Int).Sqrt(disc)
		if new(big.Int).Mul(sqrtD, sqrtD).Cmp(disc) != 0 {
			continue
		}
		p := new(big.Int).Add(s, sqrtD)
		if p.Sign() > 0 && new(big.Int).Mod(p, big.NewInt(2)).Sign() == 0 {
			p.Div(p, big.NewInt(2))
			q := new(big.Int).Div(n, p)
			if new(big.Int).Mul(p, q).Cmp(n) == 0 {
				return d
			}
		}
	}
	return nil
}

func continuedFraction(a, b *big.Int) []*big.Int {
	var terms []*big.Int
	curA := new(big.Int).Set(a)
	curB := new(big.Int).Set(b)
	for curB.Sign() != 0 {
		q := new(big.Int).Div(curA, curB)
		terms = append(terms, q)
		r := new(big.Int).Mod(curA, curB)
		curA = curB
		curB = r
		if len(terms) > 200 {
			break
		}
	}
	return terms
}

func convergentsOf(a, b *big.Int, limit int) [][2]*big.Int {
	terms := continuedFraction(a, b)
	if limit < len(terms) {
		terms = terms[:limit]
	}
	var out [][2]*big.Int
	hPrev, hPrev2 := big.NewInt(0), big.NewInt(1)
	kPrev, kPrev2 := big.NewInt(1), big.NewInt(0)
	for _, t := range terms {
		h := new(big.Int).Mul(t, hPrev)
		h.Add(h, hPrev2)
		k := new(big.Int).Mul(t, kPrev)
		k.Add(k, kPrev2)
		out = append(out, [2]*big.Int{new(big.Int).Set(h), new(big.Int).Set(k)})
		hPrev2, hPrev = hPrev, h
		kPrev2, kPrev = kPrev, k
	}
	return out
}

func joinBigs(b []*big.Int) string {
	parts := make([]string, len(b))
	for i, v := range b {
		parts[i] = v.String()
	}
	return strings.Join(parts, " * ")
}
