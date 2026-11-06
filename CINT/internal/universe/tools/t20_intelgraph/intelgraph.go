package t20_intelgraph

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	core "github.com/brezzkin-dev/CINT/internal/universe/core"
)

type Node struct {
	ID    string            `json:"id"`
	Type  string            `json:"type"`
	Attrs map[string]string `json:"attrs,omitempty"`
}

type Edge struct {
	From string `json:"from"`
	To   string `json:"to"`
	Rel  string `json:"rel"`
}

var (
	reIPv4   = regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b`)
	reDomain = regexp.MustCompile(`\b([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b`)
	reEmail  = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`)
	reHash   = regexp.MustCompile(`\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b`)
	reURL    = regexp.MustCompile(`https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{4,}`)
)

func Run(inputs []string, format, outPath string) (*core.Result, error) {
	r := core.NewResult("intelgraph", strings.Join(inputs, ","))

	nodes := map[string]*Node{}
	edges := map[string]*Edge{}
	addNode := func(id, typ string, attrs map[string]string) {
		if _, ok := nodes[id]; !ok {
			nodes[id] = &Node{ID: id, Type: typ, Attrs: attrs}
		}
	}
	addEdge := func(from, to, rel string) {
		key := from + "|" + to + "|" + rel
		if _, ok := edges[key]; !ok {
			edges[key] = &Edge{From: from, To: to, Rel: rel}
		}
	}

	for _, in := range inputs {
		data, err := os.ReadFile(in)
		if err != nil {
			core.Warnf("skip %s: %v", in, err)
			continue
		}
		var raw map[string]any
		if err := json.Unmarshal(data, &raw); err != nil {
			core.Warnf("bad json %s: %v", in, err)
			continue
		}
		reportTag := filepath.Base(in)
		scanString(reportTag, "", raw, addNode, addEdge)
		if tool, ok := raw["tool"].(string); ok {
			addNode(reportTag, "report", map[string]string{"tool": tool})
		}
	}

	switch format {
	case "json":
		writeJSONFile(outPath, nodes, edges)
	case "text":
		writeTextFile(outPath, nodes, edges)
	default:
		writeDOTFile(outPath, nodes, edges)
	}

	nodeList := make([]Node, 0, len(nodes))
	for _, n := range nodes {
		nodeList = append(nodeList, *n)
	}
	edgeList := make([]Edge, 0, len(edges))
	for _, e := range edges {
		edgeList = append(edgeList, *e)
	}
	sort.Slice(nodeList, func(i, j int) bool { return nodeList[i].ID < nodeList[j].ID })
	r.AddExtra("nodes", nodeList)
	r.AddExtra("edges", edgeList)
	r.AddExtra("node_count", len(nodes))
	r.AddExtra("edge_count", len(edges))
	r.AddExtra("format", format)
	if outPath != "" {
		r.AddExtra("output", outPath)
	}
	r.Add(core.Finding{Tool: "intelgraph", Severity: core.SevInfo,
		Title:  fmt.Sprintf("Graph: %d nodes, %d edges", len(nodes), len(edges)),
		Detail: outPath})

	r.Finish()
	return r, nil
}

func scanString(report, parent string, v any, addNode func(string, string, map[string]string), addEdge func(string, string, string)) {
	switch x := v.(type) {
	case string:
		for _, m := range reURL.FindAllString(x, -1) {
			addNode(m, "url", nil)
			if parent != "" {
				addEdge(parent, m, "contains")
			}
			addEdge(report, m, "mentions")
		}
		for _, m := range reEmail.FindAllString(x, -1) {
			addNode(m, "email", nil)
			addEdge(report, m, "mentions")
			if at := strings.LastIndex(m, "@"); at >= 0 {
				dom := m[at+1:]
				addNode(dom, "domain", nil)
				addEdge(m, dom, "belongs_to")
			}
		}
		for _, m := range reIPv4.FindAllString(x, -1) {
			if m == "0.0.0.0" || m == "127.0.0.1" || m == "255.255.255.255" {
				continue
			}
			addNode(m, "ip", nil)
			addEdge(report, m, "mentions")
		}
		for _, m := range reHash.FindAllString(x, -1) {
			addNode(strings.ToLower(m), "hash", nil)
			addEdge(report, m, "mentions")
		}
		for _, m := range reDomain.FindAllString(x, -1) {
			if strings.Contains(m, "://") || strings.Contains(m, "@") {
				continue
			}
			if isLikelyDomain(m) {
				addNode(m, "domain", nil)
				addEdge(report, m, "mentions")
			}
		}
	case []any:
		for _, item := range x {
			scanString(report, parent, item, addNode, addEdge)
		}
	case map[string]any:
		for _, item := range x {
			newParent := parent
			if parent == "" {
				newParent = report
			}
			scanString(report, newParent, item, addNode, addEdge)
		}
	}
}

func isLikelyDomain(s string) bool {
	if strings.ContainsAny(s, "/\\:") {
		return false
	}
	if !strings.Contains(s, ".") {
		return false
	}
	onlyDigitsDots := true
	for _, c := range s {
		if c != '.' && (c < '0' || c > '9') {
			onlyDigitsDots = false
			break
		}
	}
	if onlyDigitsDots {
		return false
	}
	tld := s[strings.LastIndex(s, ".")+1:]
	return len(tld) >= 2 && len(tld) <= 24
}

func writeDOTFile(path string, nodes map[string]*Node, edges map[string]*Edge) {
	var b strings.Builder
	b.WriteString("digraph intel {\n")
	b.WriteString("  rankdir=LR;\n")
	b.WriteString("  node [shape=box, style=rounded, fontname=\"Helvetica\"];\n")

	colorFor := func(t string) string {
		switch t {
		case "ip":
			return "#e74c3c"
		case "domain":
			return "#3498db"
		case "email":
			return "#2ecc71"
		case "hash":
			return "#f39c12"
		case "url":
			return "#9b59b6"
		case "report":
			return "#95a5a6"
		}
		return "#bdc3c7"
	}

	nodeIDs := make([]string, 0, len(nodes))
	for id := range nodes {
		nodeIDs = append(nodeIDs, id)
	}
	sort.Strings(nodeIDs)
	for _, id := range nodeIDs {
		n := nodes[id]
		fmt.Fprintf(&b, "  \"%s\" [fillcolor=\"%s\", style=\"rounded,filled\"];\n",
			escapeDOT(id), colorFor(n.Type))
	}

	edgeKeys := make([]string, 0, len(edges))
	for k := range edges {
		edgeKeys = append(edgeKeys, k)
	}
	sort.Strings(edgeKeys)
	for _, k := range edgeKeys {
		e := edges[k]
		fmt.Fprintf(&b, "  \"%s\" -> \"%s\" [label=\"%s\"];\n",
			escapeDOT(e.From), escapeDOT(e.To), escapeDOT(e.Rel))
	}
	b.WriteString("}\n")

	if path == "" {
		fmt.Print(b.String())
		return
	}
	os.WriteFile(path, []byte(b.String()), 0644)
	fmt.Fprintf(os.Stderr, "wrote: %s\n", path)
}

func writeJSONFile(path string, nodes map[string]*Node, edges map[string]*Edge) {
	nodeList := make([]*Node, 0, len(nodes))
	for _, n := range nodes {
		nodeList = append(nodeList, n)
	}
	sort.Slice(nodeList, func(i, j int) bool { return nodeList[i].ID < nodeList[j].ID })
	edgeList := make([]*Edge, 0, len(edges))
	for _, e := range edges {
		edgeList = append(edgeList, e)
	}
	sort.Slice(edgeList, func(i, j int) bool {
		if edgeList[i].From != edgeList[j].From {
			return edgeList[i].From < edgeList[j].From
		}
		return edgeList[i].To < edgeList[j].To
	})
	out := map[string]any{"nodes": nodeList, "edges": edgeList}
	b, _ := json.MarshalIndent(out, "", "  ")
	if path == "" {
		os.Stdout.Write(b)
		os.Stdout.Write([]byte("\n"))
		return
	}
	os.WriteFile(path, b, 0644)
	fmt.Fprintf(os.Stderr, "wrote: %s\n", path)
}

func writeTextFile(path string, nodes map[string]*Node, edges map[string]*Edge) {
	var b strings.Builder
	byType := map[string][]string{}
	for id, n := range nodes {
		byType[n.Type] = append(byType[n.Type], id)
	}
	types := make([]string, 0, len(byType))
	for t := range byType {
		types = append(types, t)
	}
	sort.Strings(types)
	for _, t := range types {
		sort.Strings(byType[t])
		fmt.Fprintf(&b, "[%s] (%d)\n", t, len(byType[t]))
		for _, id := range byType[t] {
			fmt.Fprintf(&b, "  %s\n", id)
		}
	}
	b.WriteString("\n[edges]\n")
	edgeKeys := make([]string, 0, len(edges))
	for k := range edges {
		edgeKeys = append(edgeKeys, k)
	}
	sort.Strings(edgeKeys)
	for _, k := range edgeKeys {
		e := edges[k]
		fmt.Fprintf(&b, "  %s -[%s]-> %s\n", e.From, e.Rel, e.To)
	}
	if path == "" {
		fmt.Print(b.String())
		return
	}
	os.WriteFile(path, []byte(b.String()), 0644)
	fmt.Fprintf(os.Stderr, "wrote: %s\n", path)
}

func escapeDOT(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return s
}
