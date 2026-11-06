package t05_userfinder

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	core "github.com/brezzkin-dev/CINT/internal/universe/core"
)

// Status is a truthful classification. Only StatusConfirmed indicates a
// most-likely-existing account. Everything else is explicitly labeled.
type Status string

const (
	StatusConfirmed Status = "confirmed"
	StatusPossible  Status = "possible"
	StatusNotFound  Status = "not_found"
	StatusBlocked   Status = "blocked"
	StatusUnknown   Status = "unknown"
)

type Checker struct {
	Name     string
	URL      string
	Classify func(status int, body []byte) (Status, string)
}

var platforms = []Checker{
	{"GitHub", "https://github.com/%s", statusBased()},
	{"GitLab", "https://gitlab.com/%s", statusBased()},
	{"Reddit", "https://www.reddit.com/user/%s/about.json", bodyMarkerBased("karma")},
	{"HackerNews", "https://news.ycombinator.com/user?id=%s", bodyMarkerBased("karma")},
	{"Keybase", "https://keybase.io/%s", statusBased()},
	{"Dev.to", "https://dev.to/%s", statusBased()},
	{"Medium", "https://medium.com/@%s", statusBased()},
	{"Steam", "https://steamcommunity.com/id/%s", bodyMarkerBased("profile_header")},
	{"Telegram", "https://t.me/%s", statusBased()},
	{"Twitch", "https://www.twitch.tv/%s", statusBased()},
	{"VK", "https://vk.com/%s", statusBased()},
	{"Mastodon", "https://mastodon.social/@%s", statusBased()},
	{"SoundCloud", "https://soundcloud.com/%s", statusBased()},
	{"YouTube", "https://www.youtube.com/@%s", statusBased()},
	{"Flickr", "https://www.flickr.com/people/%s", statusBased()},
	{"Pinterest", "https://www.pinterest.com/%s/", statusBased()},
	{"TikTok", "https://www.tiktok.com/@%s", statusBased()},
	{"Instagram", "https://www.instagram.com/%s/", statusBased()},
	{"Nitter/X", "https://nitter.net/%s", statusBased()},
}

type Hit struct {
	Name       string `json:"name"`
	URL        string `json:"url"`
	Status     Status `json:"status"`
	HTTPStatus int    `json:"http_status"`
	Evidence   string `json:"evidence,omitempty"`
}

func Run(username string) (*core.Result, error) {
	r := core.NewResult("userfinder", username)
	username = strings.TrimSpace(username)
	if username == "" {
		return r, fmt.Errorf("empty username")
	}
	if !isSafeUsername(username) {
		return r, fmt.Errorf("username contains invalid characters")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	var hits []Hit
	seenURLs := map[string]bool{}

	for _, p := range platforms {
		u := fmt.Sprintf(p.URL, username)
		if seenURLs[u] {
			continue
		}
		seenURLs[u] = true
		wg.Add(1)
		go func(p Checker, u string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			status, _, body, err := core.HTTPGet(ctx, u, nil)
			cls := StatusUnknown
			evidence := ""
			if err != nil {
				evidence = err.Error()
			} else {
				cls, evidence = p.Classify(status, body)
			}
			mu.Lock()
			hits = append(hits, Hit{
				Name: p.Name, URL: u, Status: cls,
				HTTPStatus: status, Evidence: evidence,
			})
			mu.Unlock()

			if cls == StatusConfirmed {
				r.Add(core.Finding{
					Tool: "userfinder", Severity: core.SevInfo,
					Title:    "confirmed: " + p.Name,
					Detail:   u,
					Evidence: map[string]any{"http_status": status},
				})
			}
		}(p, u)
	}
	wg.Wait()

	counts := map[Status]int{}
	for _, h := range hits {
		counts[h.Status]++
	}
	r.AddExtra("username", username)
	r.AddExtra("hits", hits)
	r.AddExtra("confirmed", counts[StatusConfirmed])
	r.AddExtra("possible", counts[StatusPossible])
	r.AddExtra("not_found", counts[StatusNotFound])
	r.AddExtra("blocked", counts[StatusBlocked])
	r.AddExtra("unknown", counts[StatusUnknown])
	r.Finish()
	return r, nil
}

func isSafeUsername(s string) bool {
	if len(s) == 0 || len(s) > 64 {
		return false
	}
	for _, c := range s {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}

func statusBased() func(int, []byte) (Status, string) {
	return func(status int, _ []byte) (Status, string) {
		switch {
		case status == 200:
			return StatusConfirmed, "200 OK"
		case status == 404:
			return StatusNotFound, "404"
		case status == 401, status == 403, status == 429:
			return StatusBlocked, fmt.Sprintf("HTTP %d (blocked/rate-limited)", status)
		case status >= 300 && status < 400:
			return StatusUnknown, fmt.Sprintf("HTTP %d redirect", status)
		case status >= 500:
			return StatusUnknown, fmt.Sprintf("HTTP %d server error", status)
		}
		return StatusUnknown, fmt.Sprintf("HTTP %d", status)
	}
}

func bodyMarkerBased(marker string) func(int, []byte) (Status, string) {
	return func(status int, body []byte) (Status, string) {
		if status != 200 {
			return statusBased()(status, body)
		}
		if strings.Contains(strings.ToLower(string(body)), marker) {
			return StatusConfirmed, "body marker: " + marker
		}
		return StatusPossible, "200 but marker missing"
	}
}
