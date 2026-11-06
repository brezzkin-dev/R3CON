package t19_timelinex

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	core "github.com/brezzkin-dev/CINT/internal/universe/core"
)

type Options struct {
	Inputs []string
	From   string
	To     string
}

type Event struct {
	TS     time.Time `json:"-"`
	TSStr  string    `json:"ts"`
	Source string    `json:"source"`
	Kind   string    `json:"kind"`
	Msg    string    `json:"msg"`
	Extra  string    `json:"extra,omitempty"`
}

var reSyslog = regexp.MustCompile(`^(\w{3}\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+([\w\-\.\/\[\]]+):\s+(.*)$`)

func Run(opts Options) (*core.Result, error) {
	r := core.NewResult("timelinex", strings.Join(opts.Inputs, ","))

	var from, to time.Time
	if opts.From != "" {
		from, _ = time.Parse(time.RFC3339, opts.From)
	}
	if opts.To != "" {
		to, _ = time.Parse(time.RFC3339, opts.To)
	}

	var events []Event
	seen := map[string]bool{}

	for _, in := range opts.Inputs {
		info, err := os.Stat(in)
		if err != nil {
			core.Warnf("skip %s: %v", in, err)
			continue
		}
		if info.IsDir() {
			walkDir(in, &events, seen)
		} else {
			parseFile(in, &events, seen)
		}
	}

	if !from.IsZero() || !to.IsZero() {
		var filtered []Event
		for _, e := range events {
			if !from.IsZero() && e.TS.Before(from) {
				continue
			}
			if !to.IsZero() && e.TS.After(to) {
				continue
			}
			filtered = append(filtered, e)
		}
		events = filtered
	}

	sort.Slice(events, func(i, j int) bool { return events[i].TS.Before(events[j].TS) })

	for i := range events {
		events[i].TSStr = events[i].TS.UTC().Format(time.RFC3339)
	}

	r.AddExtra("event_count", len(events))
	r.AddExtra("timeline", events)

	if len(events) > 0 {
		r.AddExtra("first", events[0].TSStr)
		r.AddExtra("last", events[len(events)-1].TSStr)
		r.Add(core.Finding{Tool: "timelinex", Severity: core.SevInfo,
			Title: "Timeline built",
			Detail: intToString(len(events)) + " events · " +
				events[0].TSStr + " → " + events[len(events)-1].TSStr,
		})
	}

	r.Finish()
	return r, nil
}

func walkDir(root string, events *[]Event, seen map[string]bool) {
	filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		key := "fs:" + p + ":" + info.ModTime().Format(time.RFC3339)
		if seen[key] {
			return nil
		}
		seen[key] = true
		*events = append(*events, Event{
			TS:     info.ModTime(),
			Source: "filesystem",
			Kind:   "file_mtime",
			Msg:    p,
			Extra:  intToString(int(info.Size())) + " bytes",
		})
		return nil
	})
}

func parseFile(path string, events *[]Event, seen map[string]bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}

	var jsonArr []map[string]any
	if json.Unmarshal(data, &jsonArr) == nil && len(jsonArr) > 0 {
		parseJSONEvents(jsonArr, path, events, seen)
		return
	}

	sc := bufio.NewScanner(strings.NewReader(string(data)))
	sc.Buffer(make([]byte, 4096), 16<<20)
	jsonl := false
	var lines []string
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	for _, l := range lines {
		var m map[string]any
		if json.Unmarshal([]byte(l), &m) == nil && (m["ts"] != nil || m["time"] != nil) {
			jsonl = true
			break
		}
	}
	if jsonl {
		var entries []map[string]any
		for _, l := range lines {
			var m map[string]any
			if json.Unmarshal([]byte(l), &m) == nil {
				entries = append(entries, m)
			}
		}
		parseJSONEvents(entries, path, events, seen)
		return
	}

	if strings.HasSuffix(path, "wtmp") || looksBinary(data) {
		if parseWtmp(data, path, events, seen) {
			return
		}
	}

	parseSyslog(lines, path, events, seen)
}

func parseJSONEvents(arr []map[string]any, source string, events *[]Event, seen map[string]bool) {
	for _, m := range arr {
		tsStr := ""
		for _, k := range []string{"ts", "time", "timestamp", "added_at"} {
			if v, ok := m[k].(string); ok {
				tsStr = v
				break
			}
		}
		if tsStr == "" {
			continue
		}
		t, err := time.Parse(time.RFC3339, tsStr)
		if err != nil {
			t, err = time.Parse("2006-01-02T15:04:05", tsStr)
			if err != nil {
				continue
			}
		}
		kind := "event"
		if v, ok := m["kind"].(string); ok {
			kind = v
		} else if v, ok := m["title"].(string); ok {
			kind = v
		}
		msg := ""
		for _, k := range []string{"msg", "detail", "title"} {
			if v, ok := m[k].(string); ok && v != "" {
				msg = v
				break
			}
		}
		key := source + ":" + tsStr + ":" + msg
		if seen[key] {
			continue
		}
		seen[key] = true
		*events = append(*events, Event{TS: t, Source: source, Kind: kind, Msg: msg})
	}
}

func parseSyslog(lines []string, source string, events *[]Event, seen map[string]bool) {
	year := time.Now().Year()
	for _, line := range lines {
		m := reSyslog.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		ts, err := time.Parse("Jan 2 15:04:05 2006",
			strings.Join(strings.Fields(m[1]), " ")+" "+intToString(year))
		if err != nil {
			continue
		}
		key := source + ":" + ts.Format(time.RFC3339) + ":" + m[4]
		if seen[key] {
			continue
		}
		seen[key] = true
		*events = append(*events, Event{
			TS: ts, Source: source, Kind: "syslog",
			Msg: m[4], Extra: m[2] + " " + m[3],
		})
	}
}

func parseWtmp(data []byte, source string, events *[]Event, seen map[string]bool) bool {
	const rec = 384
	if len(data) < rec {
		return false
	}
	parsed := 0
	for i := 0; i+rec <= len(data); i += rec {
		recData := data[i : i+rec]
		utType := int16(binary.LittleEndian.Uint16(recData[0:2]))
		ts := int32(binary.LittleEndian.Uint32(recData[340:344]))
		if ts <= 0 {
			continue
		}
		user := cstr(recData[44:76])
		line := cstr(recData[8:40])
		host := cstr(recData[76:332])
		kind := "wtmp"
		switch utType {
		case 7:
			kind = "login"
		case 8:
			kind = "logout"
		case 2:
			kind = "boot"
		}
		t := time.Unix(int64(ts), 0)
		key := source + ":" + t.UTC().Format(time.RFC3339) + ":" + user
		if seen[key] {
			continue
		}
		seen[key] = true
		*events = append(*events, Event{
			TS: t, Source: source, Kind: kind,
			Msg: user + " tty=" + line, Extra: host,
		})
		parsed++
	}
	return parsed > 0
}

func looksBinary(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	zeros := 0
	for _, c := range data[:minInt(64, len(data))] {
		if c == 0 {
			zeros++
		}
	}
	return zeros > 8
}

func cstr(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func intToString(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
