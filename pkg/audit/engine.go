package audit

import (
	"context"
	"fmt"
	"time"

	"github.com/Siovos/siovos-audit/pkg/collector"
)

// Scorer calculates scores from a set of findings.
type Scorer interface {
	Score(findings []Finding) ScoreResult
}

// Engine orchestrates an audit: it runs checks via a collector, collects findings,
// and passes them through the scorer to produce a final result.
type Engine struct {
	registry *Registry
	scorer   Scorer
}

// NewEngine creates an engine with the given registry and scorer.
func NewEngine(registry *Registry, scorer Scorer) *Engine {
	return &Engine{
		registry: registry,
		scorer:   scorer,
	}
}

// Run executes the selected checks (or all if checkIDs is empty) and returns the audit result.
func (e *Engine) Run(ctx context.Context, col collector.Collector, checkIDs []string) (*AuditResult, error) {
	checks := e.registry.Filter(checkIDs)
	if len(checks) == 0 {
		return nil, fmt.Errorf("no checks to run")
	}

	result := &AuditResult{
		Target:    col.Target(),
		StartedAt: time.Now(),
	}

	platform := col.Platform()
	result.Platform = PlatformInfo{
		OS:     platform.OS,
		Arch:   platform.Arch,
		Distro: platform.Distro,
		Kernel: platform.Kernel,
	}

	for _, check := range checks {
		findings, err := check.Run(ctx, col)
		if err != nil {
			result.Findings = append(result.Findings, Finding{
				ID:       check.ID() + "-error",
				CheckID:  check.ID(),
				Severity: SeverityWarn,
				Title:    fmt.Sprintf("Check %s failed to run", check.Name()),
				Evidence: err.Error(),
			})
			continue
		}
		result.Findings = append(result.Findings, findings...)
	}

	result.FinishedAt = time.Now()
	result.Score = e.scorer.Score(result.Findings)

	return result, nil
}
