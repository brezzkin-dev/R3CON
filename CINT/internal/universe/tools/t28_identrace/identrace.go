package t28_identrace

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	core "github.com/brezzkin-dev/CINT/internal/universe/core"
)

type Profile struct {
	Platform string         `json:"platform"`
	URL      string         `json:"url"`
	Found    bool           `json:"found"`
	Data     map[string]any `json:"data,omitempty"`
	Error    string         `json:"error,omitempty"`
}

func Run(username, email string) (*core.Result, error) {
	r := core.NewResult("identrace", firstNonEmpty(username, email))
	username = strings.TrimSpace(username)
	email = strings.TrimSpace(email)

	if username != "" && !isSafe(username) {
		return r, fmt.Errorf("invalid username")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var profiles []Profile
	var mu sync.Mutex
	var wg sync.WaitGroup

	addProfile := func(p Profile) {
		mu.Lock()
		profiles = append(profiles, p)
		mu.Unlock()
	}

	if username != "" {
		lookups := []func(context.Context, string) Profile{
			lookupGitHub, lookupReddit, lookupHackerNews,
			lookupKeybase, lookupMastodon,
		}
		for _, fn := range lookups {
			wg.Add(1)
			go func(f func(context.Context, string) Profile) {
				defer wg.Done()
				addProfile(f(ctx, username))
			}(fn)
		}
	}

	if email != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			addProfile(lookupGravatar(ctx, email))
		}()
	}

	wg.Wait()

	found := 0
	for _, p := range profiles {
		if p.Found {
			found++
			detail := p.URL
			if p.Data != nil {
				if name, ok := p.Data["name"].(string); ok && name != "" {
					detail = name + " — " + p.URL
				}
			}
			r.Add(core.Finding{
				Tool: "identrace", Severity: core.SevInfo,
				Title:  "profile: " + p.Platform,
				Detail: detail,
			})
		}
	}

	r.AddExtra("username", username)
	r.AddExtra("email", email)
	r.AddExtra("profiles", profiles)
	r.AddExtra("found_count", found)
	r.Finish()
	return r, nil
}

func lookupGitHub(ctx context.Context, user string) Profile {
	u := "https://api.github.com/users/" + url.PathEscape(user)
	p := Profile{Platform: "github", URL: "https://github.com/" + user}
	status, _, body, err := core.HTTPGet(ctx, u,
		map[string]string{"Accept": "application/vnd.github+json"})
	if err != nil {
		p.Error = err.Error()
		return p
	}
	if status == 404 {
		return p
	}
	if status != 200 {
		p.Error = fmt.Sprintf("http %d", status)
		return p
	}
	var data map[string]any
	if err := json.Unmarshal(body, &data); err != nil {
		p.Error = err.Error()
		return p
	}
	p.Found = true
	p.Data = map[string]any{
		"name":         data["name"],
		"bio":          data["bio"],
		"company":      data["company"],
		"location":     data["location"],
		"public_repos": data["public_repos"],
		"followers":    data["followers"],
		"created_at":   data["created_at"],
	}
	return p
}

func lookupReddit(ctx context.Context, user string) Profile {
	u := "https://www.reddit.com/user/" + url.PathEscape(user) + "/about.json"
	p := Profile{Platform: "reddit", URL: "https://www.reddit.com/user/" + user}
	status, _, body, err := core.HTTPGet(ctx, u,
		map[string]string{"User-Agent": "CINT-OSINT/1.0"})
	if err != nil {
		p.Error = err.Error()
		return p
	}
	if status == 404 {
		return p
	}
	if status != 200 {
		p.Error = fmt.Sprintf("http %d", status)
		return p
	}
	var out struct {
		Data struct {
			Name         string  `json:"name"`
			Created      float64 `json:"created_utc"`
			CommentKarma float64 `json:"comment_karma"`
			LinkKarma    float64 `json:"link_karma"`
			IsMod        bool    `json:"is_mod"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		p.Error = err.Error()
		return p
	}
	if out.Data.Name == "" {
		return p
	}
	p.Found = true
	p.Data = map[string]any{
		"name":          out.Data.Name,
		"comment_karma": out.Data.CommentKarma,
		"link_karma":    out.Data.LinkKarma,
		"is_mod":        out.Data.IsMod,
		"created_utc":   out.Data.Created,
	}
	return p
}

func lookupHackerNews(ctx context.Context, user string) Profile {
	u := "https://hacker-news.firebaseio.com/v0/user/" + url.PathEscape(user) + ".json"
	p := Profile{Platform: "hackernews", URL: "https://news.ycombinator.com/user?id=" + user}
	status, _, body, err := core.HTTPGet(ctx, u, nil)
	if err != nil {
		p.Error = err.Error()
		return p
	}
	if status != 200 || string(body) == "null" {
		return p
	}
	var data map[string]any
	if err := json.Unmarshal(body, &data); err != nil {
		p.Error = err.Error()
		return p
	}
	p.Found = true
	p.Data = map[string]any{
		"id":      data["id"],
		"karma":   data["karma"],
		"created": data["created"],
		"about":   data["about"],
	}
	return p
}

func lookupKeybase(ctx context.Context, user string) Profile {
	u := "https://keybase.io/_/api/1.0/user/lookup.json?username=" + url.QueryEscape(user)
	p := Profile{Platform: "keybase", URL: "https://keybase.io/" + user}
	status, _, body, err := core.HTTPGet(ctx, u, nil)
	if err != nil {
		p.Error = err.Error()
		return p
	}
	if status != 200 {
		p.Error = fmt.Sprintf("http %d", status)
		return p
	}
	var out struct {
		Status struct {
			Code int `json:"code"`
		} `json:"status"`
		Them []map[string]any `json:"them"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		p.Error = err.Error()
		return p
	}
	if out.Status.Code != 0 || len(out.Them) == 0 {
		return p
	}
	p.Found = true
	p.Data = out.Them[0]
	return p
}

func lookupMastodon(ctx context.Context, user string) Profile {
	u := "https://mastodon.social/api/v1/accounts/lookup?acct=" + url.QueryEscape(user)
	p := Profile{Platform: "mastodon", URL: "https://mastodon.social/@" + user}
	status, _, body, err := core.HTTPGet(ctx, u, nil)
	if err != nil {
		p.Error = err.Error()
		return p
	}
	if status != 200 {
		return p
	}
	var data map[string]any
	if err := json.Unmarshal(body, &data); err != nil {
		p.Error = err.Error()
		return p
	}
	p.Found = true
	p.Data = map[string]any{
		"username":     data["username"],
		"display_name": data["display_name"],
		"note":         data["note"],
		"followers":    data["followers_count"],
		"created_at":   data["created_at"],
	}
	return p
}

func lookupGravatar(ctx context.Context, email string) Profile {
	h := md5.Sum([]byte(strings.ToLower(strings.TrimSpace(email))))
	hashed := hex.EncodeToString(h[:])
	avatarURL := "https://www.gravatar.com/avatar/" + hashed + "?d=404"
	p := Profile{Platform: "gravatar", URL: avatarURL}
	status, _, _, err := core.HTTPGet(ctx, avatarURL, nil)
	if err != nil {
		p.Error = err.Error()
		return p
	}
	if status == 200 {
		p.Found = true
		p.Data = map[string]any{"hash": hashed}
	}
	return p
}

func isSafe(s string) bool {
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

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}
