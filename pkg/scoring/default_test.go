package scoring_test

import (
	"testing"

	"github.com/Siovos/siovos-audit/pkg/audit"
	"github.com/Siovos/siovos-audit/pkg/scoring"
)

func TestDefaultScorer_AllPass(t *testing.T) {
	s := scoring.NewDefaultScorer()
	findings := []audit.Finding{
		{CheckID: "ssh", Severity: audit.SeverityPass},
		{CheckID: "ssh", Severity: audit.SeverityPass},
	}

	result := s.Score(findings)
	if result.Overall != 100 {
		t.Errorf("all pass: got overall %d, want 100", result.Overall)
	}
}

func TestDefaultScorer_MixedSeverities(t *testing.T) {
	s := scoring.NewDefaultScorer()
	findings := []audit.Finding{
		{CheckID: "ssh", Severity: audit.SeverityPass},
		{CheckID: "ssh", Severity: audit.SeverityFail},  // -15
		{CheckID: "ssh", Severity: audit.SeverityWarn},   // -5
	}

	result := s.Score(findings)
	// 100 - 15 - 5 = 80
	if result.Categories["ssh"].Score != 80 {
		t.Errorf("ssh score: got %d, want 80", result.Categories["ssh"].Score)
	}
}

func TestDefaultScorer_CriticalDeduction(t *testing.T) {
	s := scoring.NewDefaultScorer()
	findings := []audit.Finding{
		{CheckID: "ssh", Severity: audit.SeverityPass},
		{CheckID: "ssh", Severity: audit.SeverityCritical}, // -25
	}

	result := s.Score(findings)
	if result.Categories["ssh"].Score != 75 {
		t.Errorf("ssh score: got %d, want 75", result.Categories["ssh"].Score)
	}
}

func TestDefaultScorer_FloorAtZero(t *testing.T) {
	s := scoring.NewDefaultScorer()
	findings := []audit.Finding{
		{CheckID: "ssh", Severity: audit.SeverityCritical}, // -25
		{CheckID: "ssh", Severity: audit.SeverityCritical}, // -25
		{CheckID: "ssh", Severity: audit.SeverityCritical}, // -25
		{CheckID: "ssh", Severity: audit.SeverityCritical}, // -25
		{CheckID: "ssh", Severity: audit.SeverityCritical}, // -25
	}

	result := s.Score(findings)
	if result.Categories["ssh"].Score != 0 {
		t.Errorf("score should floor at 0, got %d", result.Categories["ssh"].Score)
	}
}

func TestDefaultScorer_MultiCategory(t *testing.T) {
	s := scoring.NewDefaultScorer()
	findings := []audit.Finding{
		{CheckID: "ssh", Severity: audit.SeverityPass},     // ssh: 100
		{CheckID: "firewall", Severity: audit.SeverityFail}, // firewall: 85
	}

	result := s.Score(findings)
	if result.Categories["ssh"].Score != 100 {
		t.Errorf("ssh: got %d, want 100", result.Categories["ssh"].Score)
	}
	if result.Categories["firewall"].Score != 85 {
		t.Errorf("firewall: got %d, want 85", result.Categories["firewall"].Score)
	}
	// Overall = (100 + 85) / 2 = 92
	if result.Overall != 92 {
		t.Errorf("overall: got %d, want 92", result.Overall)
	}
}

func TestDefaultScorer_NoFindings(t *testing.T) {
	s := scoring.NewDefaultScorer()
	result := s.Score(nil)
	if result.Overall != 0 {
		t.Errorf("no findings: got overall %d, want 0", result.Overall)
	}
}
