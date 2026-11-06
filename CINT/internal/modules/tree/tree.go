package tree

import (
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"

	"github.com/brezzkin-dev/CINT/internal/core"
)

type Node struct {
	Name     string
	IsDir    bool
	Size     int64
	Children map[string]*Node
}

func Build(entries []core.FileEntry) *Node {
	root := &Node{Name: ".", IsDir: true, Children: map[string]*Node{}}
	sep := string(filepath.Separator)
	for _, e := range entries {
		parts := strings.Split(e.RelPath, sep)
		cur := root
		for i, p := range parts {
			if p == "" {
				continue
			}
			child, ok := cur.Children[p]
			if !ok {
				child = &Node{Name: p, IsDir: i < len(parts)-1, Children: map[string]*Node{}}
				cur.Children[p] = child
			}
			if i == len(parts)-1 && !e.IsDir {
				child.Size = e.Size
			}
			cur = child
		}
	}
	return root
}

func Render(n *Node, prefix string, w io.Writer) {
	keys := make([]string, 0, len(n.Children))
	for k := range n.Children {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for i, k := range keys {
		c := n.Children[k]
		connector := "├── "
		if i == len(keys)-1 {
			connector = "└── "
		}
		suffix := ""
		if !c.IsDir {
			suffix = fmt.Sprintf(" (%d B)", c.Size)
		}
		fmt.Fprintf(w, "%s%s%s%s\n", prefix, connector, c.Name, suffix)
		if c.IsDir {
			next := prefix
			if i == len(keys)-1 {
				next += "    "
			} else {
				next += "│   "
			}
			Render(c, next, w)
		}
	}
}
