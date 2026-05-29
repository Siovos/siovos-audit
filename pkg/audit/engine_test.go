package audit_test

import (
	"context"
	"testing"

	"github.com/Siovos/siovos-audit/pkg/audit"
	"github.com/Siovos/siovos-audit/pkg/collector"
	"github.com/Siovos/siovos-audit/pkg/scoring"
)

type fullMockCollector struct {
	commands map[string]string
	files    map[string]string
}

func (m *fullMockCollector) Exec(_ context.Context, cmd string) ([]byte, error) {
	if out, ok := m.commands[cmd]; ok {
		return []byte(out), nil
	}
	return nil, nil
}
func (m *fullMockCollector) ReadFile(_ context.Context, path string) ([]byte, error) {
	if content, ok := m.files[path]; ok {
		return []byte(content), nil
	}
	return nil, &mockErr{msg: "not found: " + path}
}
func (m *fullMockCollector) Platform() collector.Platform {
	return collector.Platform{OS: "linux", Distro: "Debian 13"}
}
func (m *fullMockCollector) Target() string { return "test-server" }
func (m *fullMockCollector) Close() error   { return nil }

type mockErr struct{ msg string }

func (e *mockErr) Error() string { return e.msg }

type passingCheck struct {
	id string
}

func (c *passingCheck) ID() string       { return c.id }
func (c *passingCheck) Name() string     { return c.id }
func (c *passingCheck) Category() string { return c.id }
func (c *passingCheck) Run(_ context.Context, _ collector.Collector) ([]audit.Finding, error) {
	return []audit.Finding{
		{ID: c.id + "-1", CheckID: c.id, Severity: audit.SeverityPass, Title: "OK"},
	}, nil
}

type failingCheck struct{}

func (c *failingCheck) ID() string       { return "broken" }
func (c *failingCheck) Name() string     { return "Broken" }
func (c *failingCheck) Category() string { return "broken" }
func (c *failingCheck) Run(_ context.Context, _ collector.Collector) ([]audit.Finding, error) {
	return nil, &mockErr{msg: "something went wrong"}
}

func TestEngine_RunAllChecks(t *testing.T) {
	registry := audit.NewRegistry()
	registry.Register(&passingCheck{id: "ssh"})
	registry.Register(&passingCheck{id: "firewall"})

	engine := audit.NewEngine(registry, scoring.NewDefaultScorer())
	col := &fullMockCollector{}

	result, err := engine.Run(context.Background(), col, nil)
	if err != nil {
		t.Fatal(err)
	}

	if result.Target != "test-server" {
		t.Errorf("target: got %q, want %q", result.Target, "test-server")
	}
	if len(result.Findings) != 2 {
		t.Errorf("findings: got %d, want 2", len(result.Findings))
	}
	if result.Score.Overall != 100 {
		t.Errorf("score: got %d, want 100", result.Score.Overall)
	}
}

func TestEngine_FilterChecks(t *testing.T) {
	registry := audit.NewRegistry()
	registry.Register(&passingCheck{id: "ssh"})
	registry.Register(&passingCheck{id: "firewall"})
	registry.Register(&passingCheck{id: "tls"})

	engine := audit.NewEngine(registry, scoring.NewDefaultScorer())
	col := &fullMockCollector{}

	result, err := engine.Run(context.Background(), col, []string{"ssh"})
	if err != nil {
		t.Fatal(err)
	}

	if len(result.Findings) != 1 {
		t.Errorf("findings: got %d, want 1 (filtered to ssh only)", len(result.Findings))
	}
}

func TestEngine_FailingCheckProducesWarning(t *testing.T) {
	registry := audit.NewRegistry()
	registry.Register(&failingCheck{})

	engine := audit.NewEngine(registry, scoring.NewDefaultScorer())
	col := &fullMockCollector{}

	result, err := engine.Run(context.Background(), col, nil)
	if err != nil {
		t.Fatal(err)
	}

	if len(result.Findings) != 1 {
		t.Fatalf("findings: got %d, want 1", len(result.Findings))
	}
	if result.Findings[0].Severity != audit.SeverityWarn {
		t.Errorf("failing check should produce WARN, got %s", result.Findings[0].Severity)
	}
}

func TestEngine_NoChecks(t *testing.T) {
	registry := audit.NewRegistry()
	engine := audit.NewEngine(registry, scoring.NewDefaultScorer())
	col := &fullMockCollector{}

	_, err := engine.Run(context.Background(), col, nil)
	if err == nil {
		t.Error("expected error when no checks registered")
	}
}

func TestConfig_FilterFindings(t *testing.T) {
	cfg := &audit.Config{
		Suppress: []string{"ssh-password-auth", "firewall-open-port-8080"},
	}

	findings := []audit.Finding{
		{ID: "ssh-password-auth"},
		{ID: "ssh-root-login"},
		{ID: "firewall-open-port-8080"},
		{ID: "firewall-active"},
	}

	filtered := cfg.FilterFindings(findings)
	if len(filtered) != 2 {
		t.Errorf("got %d findings, want 2", len(filtered))
	}
}
