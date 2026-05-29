package audit

import "time"

// AuditResult holds the complete output of an audit run.
type AuditResult struct {
	Target     string            `json:"target"`
	StartedAt  time.Time         `json:"started_at"`
	FinishedAt time.Time         `json:"finished_at"`
	Findings   []Finding         `json:"findings"`
	Score      ScoreResult       `json:"score"`
	Platform   PlatformInfo      `json:"platform"`
}

type PlatformInfo struct {
	OS     string `json:"os"`
	Arch   string `json:"arch"`
	Distro string `json:"distro,omitempty"`
	Kernel string `json:"kernel,omitempty"`
}

// ScoreResult holds the overall and per-category scores.
type ScoreResult struct {
	Overall    int                      `json:"overall"`
	Categories map[string]CategoryScore `json:"categories"`
}

type CategoryScore struct {
	Name   string  `json:"name"`
	Score  int     `json:"score"`
	Weight float64 `json:"weight"`
}
