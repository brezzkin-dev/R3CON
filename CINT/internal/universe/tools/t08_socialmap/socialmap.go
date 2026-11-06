package t08_socialmap

import (
	"fmt"

	core "github.com/brezzkin-dev/CINT/internal/universe/core"
	"github.com/brezzkin-dev/CINT/internal/universe/tools/t05_userfinder"
)

// Run reuses userfinder's confirmed hits and clusters them as one probable
// identity. Honest scope: this is a wrapper — a real relationship engine
// would crawl friends/followers and require explicit consent. This just
// aggregates cross-platform presence for a single handle.
func Run(username string) (*core.Result, error) {
	r := core.NewResult("socialmap", username)
	uf, err := t05_userfinder.Run(username)
	if err != nil {
		return r, err
	}

	var platforms []string
	for _, f := range uf.Findings {
		if len(f.Title) > 15 && f.Title[:15] == "confirmed: " {
			platforms = append(platforms, f.Title[11:])
		}
	}

	r.AddExtra("username", username)
	r.AddExtra("platforms", platforms)
	r.AddExtra("platform_count", len(platforms))
	r.AddExtra("userfinder", uf.Extra)

	if len(platforms) >= 3 {
		r.Add(core.Finding{
			Tool: "socialmap", Severity: core.SevMed,
			Title:    "Identity cluster",
			Detail:   fmt.Sprintf("handle appears on %d platforms — probable same person", len(platforms)),
			Evidence: map[string]any{"platforms": platforms},
		})
	}
	if len(platforms) > 0 {
		r.Add(core.Finding{
			Tool: "socialmap", Severity: core.SevInfo,
			Title: fmt.Sprintf("%d confirmed platforms", len(platforms)),
		})
	}
	r.Finish()
	return r, nil
}
