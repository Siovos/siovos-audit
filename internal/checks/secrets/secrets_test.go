package secrets_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/Siovos/siovos-audit/internal/checks/secrets"
	"github.com/Siovos/siovos-audit/pkg/audit"
	"github.com/Siovos/siovos-audit/pkg/collector"
)

type mockCollector struct {
	commands map[string]string
}

func (m *mockCollector) Exec(_ context.Context, cmd string) ([]byte, error) {
	if out, ok := m.commands[cmd]; ok {
		return []byte(out), nil
	}
	return nil, fmt.Errorf("not found")
}
func (m *mockCollector) ReadFile(_ context.Context, _ string) ([]byte, error) {
	return nil, fmt.Errorf("not found")
}
func (m *mockCollector) Platform() collector.Platform { return collector.Platform{OS: "linux"} }
func (m *mockCollector) Target() string               { return "test" }
func (m *mockCollector) Close() error                  { return nil }

func TestSecrets_CleanServer(t *testing.T) {
	col := &mockCollector{commands: map[string]string{}}

	c := secrets.New()
	findings, err := c.Run(context.Background(), col)
	if err != nil {
		t.Fatal(err)
	}

	if len(findings) != 1 || findings[0].Severity != audit.SeverityPass {
		t.Error("clean server should have single PASS finding")
	}
}

func TestSecrets_GitInWebroot(t *testing.T) {
	col := &mockCollector{commands: map[string]string{
		"test -d /var/www/html/.git && echo found 2>/dev/null": "found",
	}}

	c := secrets.New()
	findings, err := c.Run(context.Background(), col)
	if err != nil {
		t.Fatal(err)
	}

	hasCritical := false
	for _, f := range findings {
		if f.Severity == audit.SeverityCritical {
			hasCritical = true
		}
	}
	if !hasCritical {
		t.Error(".git in webroot should be CRITICAL")
	}
}
