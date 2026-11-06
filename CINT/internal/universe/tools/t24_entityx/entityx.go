package t24_entityx

import (
	"encoding/json"
	"os"
	"regexp"
	"sort"
	"strings"

	core "github.com/brezzkin-dev/CINT/internal/universe/core"
)

type Entity struct {
	Value string `json:"value"`
	Type  string `json:"type"`
	Count int    `json:"count"`
}

type Edge struct {
	A     string `json:"a"`
	B     string `json:"b"`
	Count int    `json:"count"`
}

var (
	reEmail  = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`)
	reURL    = regexp.MustCompile(`https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{6,}`)
	reIPv4   = regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b`)
	reIPv6   = regexp.MustCompile(`\b(?:[a-fA-F0-9]{1,4}:){2,7}[a-fA-F0-9]{1,4}\b`)
	reHash   = regexp.MustCompile(`\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b`)
	reDomain = regexp.MustCompile(`\b([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b`)
	rePhone  = regexp.MustCompile(`\+\d{1,3}[\s\-\.]?\(?\d{1,4}\)?[\s\-\.]?\d{3,4}[\s\-\.]?\d{3,4}[\s\-\.]?\d{0,4}`)
	rePerson = regexp.MustCompile(`\b[A-Z][a-z]{2,}(?:\s+[A-Z][a-z]{2,}){1,3}\b`)
	reOrg    = regexp.MustCompile(`\b[A-Z][A-Za-z&\.]{1,30}(?:\s+[A-Z][A-Za-z&\.]{1,20}){0,3}\s+(Inc|Ltd|LLC|Corp|GmbH|Co|SA|AG|PLC|Pty|S\.A\.)\b`)
)

const windowSize = 8

func Run(inputs []string, minCount int) (*core.Result, error) {
	r := core.NewResult("entityx", strings.Join(inputs, ","))
	if minCount < 1 {
		minCount = 2
	}

	entities := map[string]*Entity{}
	edges := map[string]*Edge{}

	addEntity := func(value, typ string) string {
		key := typ + ":" + value
		if e, ok := entities[key]; ok {
			e.Count++
			return key
		}
		entities[key] = &Entity{Value: value, Type: typ, Count: 1}
		return key
	}

	addEdge := func(a, b string) {
		if a == b {
			return
		}
		if a > b {
			a, b = b, a
		}
		key := a + "|" + b
		if e, ok := edges[key]; ok {
			e.Count++
			return
		}
		edges[key] = &Edge{A: a, B: b, Count: 1}
	}

	var allText []string
	for _, p := range inputs {
		data, err := os.ReadFile(p)
		if err != nil {
			core.Warnf("skip %s: %v", p, err)
			continue
		}
		var j any
		if json.Unmarshal(data, &j) == nil {
			allText = append(allText, flattenJSON(j)...)
			allText = append(allText, string(data))
			continue
		}
		allText = append(allText, string(data))
	}

	for _, text := range allText {
		type located struct {
			pos   int
			key   string
			value string
		}
		var locs []located
		seen := map[string]bool{}

		extra := []struct {
			rx  *regexp.Regexp
			typ string
		}{
			{reEmail, "EMAIL"},
			{reURL, "URL"},
			{reIPv4, "IP"},
			{reIPv6, "IP"},
			{reHash, "HASH"},
			{reDomain, "DOMAIN"},
			{rePhone, "PHONE"},
			{rePerson, "PERSON"},
			{reOrg, "ORG"},
		}
		for _, e := range extra {
			for _, m := range e.rx.FindAllStringIndex(text, -1) {
				val := text[m[0]:m[1]]
				if e.typ == "PERSON" {
					if !strings.Contains(val, " ") {
						continue
					}
					first := strings.SplitN(val, " ", 2)[0]
					if commonCapitalWords[first] {
						continue
					}
				}
				if e.typ == "DOMAIN" {
					if strings.Contains(val, "@") || strings.Contains(val, "://") {
						continue
					}
					if isVersionLike(val) {
						continue
					}
					if seen["DOMAIN:"+val] {
						continue
					}
				}
				key := addEntity(val, e.typ)
				seen[key] = true
				locs = append(locs, located{pos: m[0], key: key, value: val})
			}
		}

		sort.Slice(locs, func(i, j int) bool { return locs[i].pos < locs[j].pos })

		for i := 0; i < len(locs); i++ {
			for j := i + 1; j < len(locs) && j < i+windowSize; j++ {
				addEdge(locs[i].key, locs[j].key)
			}
		}
	}

	nodeList := make([]*Entity, 0, len(entities))
	for _, e := range entities {
		nodeList = append(nodeList, e)
	}
	sort.Slice(nodeList, func(i, j int) bool {
		if nodeList[i].Type != nodeList[j].Type {
			return nodeList[i].Type < nodeList[j].Type
		}
		return nodeList[i].Count > nodeList[j].Count
	})

	edgeList := make([]*Edge, 0, len(edges))
	for _, e := range edges {
		if e.Count >= minCount {
			edgeList = append(edgeList, e)
		}
	}
	sort.Slice(edgeList, func(i, j int) bool { return edgeList[i].Count > edgeList[j].Count })
	if len(edgeList) > 200 {
		edgeList = edgeList[:200]
	}

	r.AddExtra("entities", nodeList)
	r.AddExtra("edges", edgeList)
	r.AddExtra("entity_count", len(nodeList))
	r.AddExtra("edge_count", len(edgeList))

	degree := map[string]int{}
	for _, e := range edgeList {
		degree[e.A] += e.Count
		degree[e.B] += e.Count
	}
	type degRank struct {
		key   string
		count int
	}
	var ranks []degRank
	for k, v := range degree {
		ranks = append(ranks, degRank{k, v})
	}
	sort.Slice(ranks, func(i, j int) bool { return ranks[i].count > ranks[j].count })
	for i := 0; i < len(ranks) && i < 10; i++ {
		key := ranks[i].key
		if e, ok := entities[key]; ok {
			r.Add(core.Finding{
				Tool: "entityx", Severity: core.SevInfo,
				Title:  "high-degree " + e.Type,
				Detail: e.Value + " (" + itoa(ranks[i].count) + " co-occurrences)",
			})
		}
	}

	r.Finish()
	return r, nil
}

func flattenJSON(v any) []string {
	var out []string
	switch x := v.(type) {
	case string:
		out = append(out, x)
	case []any:
		for _, item := range x {
			out = append(out, flattenJSON(item)...)
		}
	case map[string]any:
		for k, item := range x {
			out = append(out, k)
			out = append(out, flattenJSON(item)...)
		}
	}
	return out
}

func isVersionLike(s string) bool {
	parts := strings.Split(s, ".")
	for _, p := range parts {
		if p == "" {
			return false
		}
		for _, c := range p {
			if c < '0' || c > '9' {
				return false
			}
		}
	}
	return len(parts) >= 3
}

var commonCapitalWords = map[string]bool{
	"The": true, "A": true, "An": true, "This": true, "That": true,
	"These": true, "Those": true, "Monday": true, "Tuesday": true,
	"Wednesday": true, "Thursday": true, "Friday": true, "Saturday": true,
	"Sunday": true, "January": true, "February": true, "March": true,
	"April": true, "May": true, "June": true, "July": true, "August": true,
	"September": true, "October": true, "November": true, "December": true,
	"Note": true, "Warning": true, "Error": true, "Success": true,
	"Total": true, "Count": true, "Message": true, "Title": true,
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
