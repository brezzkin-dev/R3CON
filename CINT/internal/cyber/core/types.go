package core

import (
	"encoding/json"
	"os"
	"time"
)

type Severity string

const (
	SevInfo Severity = "info"
	SevLow  Severity = "low"
	SevMed  Severity = "medium"
	SevHigh Severity = "high"
	SevCrit Severity = "critical"
)

func (s Severity) Rank() int {
	switch s {
	case SevCrit:
		return 5
	case SevHigh:
		return 4
	case SevMed:
		return 3
	case SevLow:
		return 2
	}
	return 1
}

type Finding struct {
	Tool     string         `json:"tool"`
	Title    string         `json:"title"`
	Severity Severity       `json:"severity"`
	Detail   string         `json:"detail"`
	Evidence map[string]any `json:"evidence,omitempty"`
}

type Result struct {
	Tool      string         `json:"tool"`
	Target    string         `json:"target"`
	StartTime string         `json:"start_time"`
	EndTime   string         `json:"end_time"`
	Findings  []Finding      `json:"findings"`
	Extra     map[string]any `json:"extra,omitempty"`
}

func NewResult(tool, target string) *Result {
	return &Result{
		Tool: tool, Target: target,
		StartTime: time.Now().UTC().Format(time.RFC3339),
		Findings:  []Finding{},
		Extra:     map[string]any{},
	}
}

func (r *Result) Add(f Finding)            { r.Findings = append(r.Findings, f) }
func (r *Result) AddExtra(k string, v any) { r.Extra[k] = v }
func (r *Result) Finish()                  { r.EndTime = time.Now().UTC().Format(time.RFC3339) }

func (r *Result) Summary() map[string]any {
	counts := map[string]int{}
	worst := SevInfo
	for _, f := range r.Findings {
		counts[string(f.Severity)]++
		if f.Severity.Rank() > worst.Rank() {
			worst = f.Severity
		}
	}
	return map[string]any{"total": len(r.Findings), "by_sev": counts, "worst": string(worst)}
}

func (r *Result) SaveJSON(path string) error {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0644)
}
