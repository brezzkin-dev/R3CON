package t29_mailscope

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	core "github.com/brezzkin-dev/CINT/internal/universe/core"
)

type Options struct {
	Verify bool
}

type Mail struct {
	From          string              `json:"from"`
	To            string              `json:"to"`
	ReplyTo       string              `json:"reply_to,omitempty"`
	ReturnPath    string              `json:"return_path,omitempty"`
	Subject       string              `json:"subject"`
	Date          string              `json:"date"`
	MessageID     string              `json:"message_id,omitempty"`
	OriginatingIP string              `json:"originating_ip,omitempty"`
	Received      []map[string]any    `json:"received,omitempty"`
	AuthResults   string              `json:"auth_results,omitempty"`
	DKIM          []DKIMResult        `json:"dkim,omitempty"`
	SPF           *SPFResult          `json:"spf,omitempty"`
	DMARC         *DMARCResult        `json:"dmarc,omitempty"`
	AllHeaders    map[string][]string `json:"all_headers,omitempty"`
}

type DKIMResult struct {
	Domain           string `json:"domain"`
	Selector         string `json:"selector"`
	Algorithm        string `json:"algorithm"`
	Canon            string `json:"canon,omitempty"`
	BodyHashPresent  bool   `json:"body_hash_present"`
	BodyHashValid    bool   `json:"body_hash_valid"`
	PubkeyPresent    bool   `json:"pubkey_present"`
	SignaturePresent bool   `json:"signature_present"`
	Error            string `json:"error,omitempty"`
}

type SPFResult struct {
	Record  string `json:"record,omitempty"`
	All     string `json:"all,omitempty"`
	Present bool   `json:"present"`
}

type DMARCResult struct {
	Record  string `json:"record,omitempty"`
	Policy  string `json:"policy,omitempty"`
	Present bool   `json:"present"`
}

var reReceivedFrom = regexp.MustCompile(`(?i)from\s+(\S+)`)
var reReceivedBy = regexp.MustCompile(`(?i)by\s+(\S+)`)
var reReceivedWith = regexp.MustCompile(`(?i)with\s+(\S+)`)

func Run(path string, opts Options) (*core.Result, error) {
	r := core.NewResult("mailscope", path)

	data, err := os.ReadFile(path)
	if err != nil {
		return r, err
	}
	headers, body := splitHeadersBody(data)
	if len(headers) == 0 {
		return r, fmt.Errorf("no headers found")
	}

	mail := parseHeaders(headers)
	mail.Received = parseReceived(mail.AllHeaders["Received"])
	mail.Received = sortReceived(mail.Received)

	if opts.Verify {
		if err := verifyDKIM(r, mail, body); err != nil {
			core.Debugf("dkim: %v", err)
		}
		if err := verifySPFDMARC(r, mail); err != nil {
			core.Debugf("spf/dmarc: %v", err)
		}
	}

	emitFindings(r, mail)
	r.AddExtra("mail", mail)
	r.Finish()
	return r, nil
}

func splitHeadersBody(data []byte) ([]byte, []byte) {
	idx := bytes.Index(data, []byte("\r\n\r\n"))
	if idx < 0 {
		idx = bytes.Index(data, []byte("\n\n"))
		if idx < 0 {
			return data, nil
		}
		return data[:idx], data[idx+2:]
	}
	return data[:idx], data[idx+4:]
}

func parseHeaders(headers []byte) *Mail {
	m := &Mail{AllHeaders: map[string][]string{}}
	sc := bufio.NewScanner(bytes.NewReader(headers))
	sc.Buffer(make([]byte, 4096), 1<<20)
	var curKey, curVal string
	flush := func() {
		if curKey == "" {
			return
		}
		key := canonicalHeader(curKey)
		val := strings.TrimSpace(curVal)
		m.AllHeaders[key] = append(m.AllHeaders[key], val)
		curKey, curVal = "", ""
	}
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
			curVal += " " + strings.TrimSpace(line)
			continue
		}
		flush()
		colon := strings.Index(line, ":")
		if colon < 0 {
			continue
		}
		curKey = line[:colon]
		curVal = line[colon+1:]
	}
	flush()

	m.From = firstHeader(m.AllHeaders, "From")
	m.To = firstHeader(m.AllHeaders, "To")
	m.ReplyTo = firstHeader(m.AllHeaders, "Reply-To")
	m.ReturnPath = firstHeader(m.AllHeaders, "Return-Path")
	m.Subject = firstHeader(m.AllHeaders, "Subject")
	m.Date = firstHeader(m.AllHeaders, "Date")
	m.MessageID = firstHeader(m.AllHeaders, "Message-Id")
	m.OriginatingIP = firstHeader(m.AllHeaders, "X-Originating-Ip")
	m.AuthResults = firstHeader(m.AllHeaders, "Authentication-Results")
	return m
}

func canonicalHeader(s string) string {
	parts := strings.SplitN(strings.TrimSpace(s), "-", 2)
	if len(parts) == 2 {
		return strings.ToUpper(parts[0][:1]) + strings.ToLower(parts[0][1:]) + "-" +
			strings.ToUpper(parts[1][:1]) + strings.ToLower(parts[1][1:])
	}
	if len(s) > 0 {
		return strings.ToUpper(s[:1]) + strings.ToLower(s[1:])
	}
	return s
}

func firstHeader(h map[string][]string, key string) string {
	if v, ok := h[key]; ok && len(v) > 0 {
		return v[0]
	}
	return ""
}

func parseReceived(headers []string) []map[string]any {
	var out []map[string]any
	for _, h := range headers {
		entry := map[string]any{"raw": h}
		if m := reReceivedFrom.FindStringSubmatch(h); len(m) > 1 {
			entry["from"] = m[1]
		}
		if m := reReceivedBy.FindStringSubmatch(h); len(m) > 1 {
			entry["by"] = m[1]
		}
		if m := reReceivedWith.FindStringSubmatch(h); len(m) > 1 {
			entry["with"] = m[1]
		}
		if semi := strings.LastIndex(h, ";"); semi >= 0 {
			ts := strings.TrimSpace(h[semi+1:])
			entry["timestamp"] = ts
			if parsed, err := parseMailDate(ts); err == nil {
				entry["ts_unix"] = parsed.Unix()
			}
		}
		out = append(out, entry)
	}
	return out
}

func sortReceived(rs []map[string]any) []map[string]any {
	sort.SliceStable(rs, func(i, j int) bool {
		ai, aok := rs[i]["ts_unix"].(int64)
		bi, bok := rs[j]["ts_unix"].(int64)
		if aok && bok {
			return ai < bi
		}
		return false
	})
	return rs
}

func parseMailDate(s string) (time.Time, error) {
	formats := []string{
		time.RFC1123Z, time.RFC1123, time.RFC822Z, time.RFC822,
		"Mon, 2 Jan 2006 15:04:05 -0700",
		"2 Jan 2006 15:04:05 -0700",
	}
	for _, f := range formats {
		if t, err := time.Parse(f, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("bad date: %s", s)
}

func verifyDKIM(r *core.Result, m *Mail, body []byte) error {
	sigs, ok := m.AllHeaders["Dkim-Signature"]
	if !ok || len(sigs) == 0 {
		return nil
	}

	canonicalBody := canonicalizeBodySimple(body)
	bodyHash := sha256.Sum256(canonicalBody)
	bodyHashB64 := base64.StdEncoding.EncodeToString(bodyHash[:])

	for _, sig := range sigs {
		dk := DKIMResult{}
		tags := parseDKIMTags(sig)
		dk.Domain = tags["d"]
		dk.Selector = tags["s"]
		dk.Algorithm = tags["a"]
		dk.Canon = tags["c"]
		bh := tags["bh"]
		dk.BodyHashPresent = bh != ""
		if dk.BodyHashPresent {
			dk.BodyHashValid = bh == bodyHashB64
		}
		dk.SignaturePresent = tags["b"] != ""

		if dk.Domain != "" && dk.Selector != "" {
			pubkeyHost := dk.Selector + "._domainkey." + dk.Domain
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			txts, err := net.DefaultResolver.LookupTXT(ctx, pubkeyHost)
			cancel()
			if err == nil {
				for _, txt := range txts {
					if strings.Contains(txt, "p=") {
						dk.PubkeyPresent = true
						break
					}
				}
			}
		}
		m.DKIM = append(m.DKIM, dk)
	}
	return nil
}

func parseDKIMTags(sig string) map[string]string {
	tags := map[string]string{}
	for _, part := range strings.Split(sig, ";") {
		part = strings.TrimSpace(part)
		eq := strings.Index(part, "=")
		if eq < 0 {
			continue
		}
		key := strings.TrimSpace(part[:eq])
		val := strings.TrimSpace(part[eq+1:])
		tags[key] = val
	}
	return tags
}

func canonicalizeBodySimple(body []byte) []byte {
	s := strings.ReplaceAll(string(body), "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	s = strings.TrimRight(s, "\n") + "\r\n"
	return []byte(s)
}

func verifySPFDMARC(r *core.Result, m *Mail) error {
	domain := extractDomain(m.From)
	if domain == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	spf := &SPFResult{}
	if txts, err := net.DefaultResolver.LookupTXT(ctx, domain); err == nil {
		for _, t := range txts {
			if strings.HasPrefix(t, "v=spf1") {
				spf.Present = true
				spf.Record = t
				if idx := strings.Index(t, "all"); idx > 0 {
					start := idx - 1
					for start > 0 && t[start-1] != ' ' {
						start--
					}
					end := idx + 3
					if end > len(t) {
						end = len(t)
					}
					spf.All = t[start:end]
				}
				break
			}
		}
	}
	m.SPF = spf

	dmarc := &DMARCResult{}
	if txts, err := net.DefaultResolver.LookupTXT(ctx, "_dmarc."+domain); err == nil {
		for _, t := range txts {
			if strings.HasPrefix(t, "v=DMARC1") {
				dmarc.Present = true
				dmarc.Record = t
				for _, part := range strings.Split(t, ";") {
					p := strings.TrimSpace(part)
					if strings.HasPrefix(p, "p=") {
						dmarc.Policy = strings.TrimPrefix(p, "p=")
						break
					}
				}
				break
			}
		}
	}
	m.DMARC = dmarc
	return nil
}

func extractDomain(from string) string {
	if lt := strings.LastIndex(from, "<"); lt >= 0 {
		from = from[lt+1:]
	}
	from = strings.TrimSuffix(from, ">")
	at := strings.LastIndex(from, "@")
	if at < 0 {
		return ""
	}
	return strings.TrimSpace(from[at+1:])
}

func emitFindings(r *core.Result, m *Mail) {
	fromDomain := extractDomain(m.From)
	returnDomain := extractDomain(m.ReturnPath)

	if fromDomain != "" && returnDomain != "" && fromDomain != returnDomain {
		r.Add(core.Finding{Tool: "mailscope", Severity: core.SevHigh,
			Title:  "From / Return-Path domain mismatch",
			Detail: fromDomain + " vs " + returnDomain})
	}
	if m.ReplyTo != "" {
		replyDomain := extractDomain(m.ReplyTo)
		if fromDomain != replyDomain && replyDomain != "" {
			r.Add(core.Finding{Tool: "mailscope", Severity: core.SevMed,
				Title:  "Reply-To differs from From",
				Detail: m.ReplyTo + " vs " + m.From})
		}
	}
	if m.SPF != nil && !m.SPF.Present {
		r.Add(core.Finding{Tool: "mailscope", Severity: core.SevMed,
			Title: "SPF missing for sender domain", Detail: fromDomain})
	}
	if m.SPF != nil && m.SPF.Present && strings.Contains(strings.ToLower(m.SPF.All), "~all") {
		r.Add(core.Finding{Tool: "mailscope", Severity: core.SevLow,
			Title: "SPF soft-fail (~all)", Detail: "not enforced"})
	}
	if m.DMARC != nil && !m.DMARC.Present {
		r.Add(core.Finding{Tool: "mailscope", Severity: core.SevMed,
			Title: "DMARC missing", Detail: fromDomain})
	}
	if m.DMARC != nil && m.DMARC.Present && m.DMARC.Policy == "none" {
		r.Add(core.Finding{Tool: "mailscope", Severity: core.SevLow,
			Title: "DMARC p=none", Detail: "monitoring only"})
	}
	for _, dk := range m.DKIM {
		if dk.BodyHashPresent && !dk.BodyHashValid {
			r.Add(core.Finding{Tool: "mailscope", Severity: core.SevHigh,
				Title:  "DKIM body hash MISMATCH",
				Detail: "message body tampered after signing"})
		}
		if dk.PubkeyPresent && dk.BodyHashValid {
			r.Add(core.Finding{Tool: "mailscope", Severity: core.SevInfo,
				Title: "DKIM body verified", Detail: dk.Domain})
		}
		if !dk.PubkeyPresent && dk.Domain != "" {
			r.Add(core.Finding{Tool: "mailscope", Severity: core.SevMed,
				Title: "DKIM pubkey missing", Detail: dk.Selector + "._domainkey." + dk.Domain})
		}
	}
	if len(m.DKIM) == 0 {
		r.Add(core.Finding{Tool: "mailscope", Severity: core.SevMed,
			Title: "No DKIM-Signature", Detail: "message is unsigned"})
	}
	if m.OriginatingIP != "" {
		r.Add(core.Finding{Tool: "mailscope", Severity: core.SevInfo,
			Title: "X-Originating-IP present", Detail: m.OriginatingIP})
	}
}
