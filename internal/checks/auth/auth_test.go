package auth_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/Siovos/siovos-audit/internal/checks/auth"
	"github.com/Siovos/siovos-audit/pkg/audit"
	"github.com/Siovos/siovos-audit/pkg/collector"
)

type mockCollector struct {
	commands map[string]string
	files    map[string]string
}

func (m *mockCollector) Exec(_ context.Context, cmd string) ([]byte, error) {
	if out, ok := m.commands[cmd]; ok {
		return []byte(out), nil
	}
	return nil, fmt.Errorf("not found")
}
func (m *mockCollector) ReadFile(_ context.Context, path string) ([]byte, error) {
	if c, ok := m.files[path]; ok {
		return []byte(c), nil
	}
	return nil, fmt.Errorf("not found")
}
func (m *mockCollector) Platform() collector.Platform { return collector.Platform{OS: "linux"} }
func (m *mockCollector) Target() string               { return "test" }
func (m *mockCollector) Close() error                  { return nil }

func factsCtx(users []audit.UserFact) context.Context {
	facts := &audit.Facts{Users: users}
	return audit.WithFacts(context.Background(), facts)
}

func TestAuth_CleanSystem(t *testing.T) {
	ctx := factsCtx([]audit.UserFact{
		{Name: "root", UID: "0", Shell: "/bin/bash", Home: "/root"},
		{Name: "www-data", UID: "33", Shell: "/usr/sbin/nologin", Home: "/var/www"},
		{Name: "deploy", UID: "1000", Shell: "/bin/bash", Home: "/home/deploy"},
	})

	col := &mockCollector{commands: map[string]string{
		"awk -F: '($2 == \"\" || $2 == \"!\") && $1 != \"root\" {print $1}' /etc/shadow 2>/dev/null": "",
		"grep -E '^ENCRYPT_METHOD' /etc/login.defs 2>/dev/null": "ENCRYPT_METHOD SHA512",
		"grep -E '^PASS_MAX_DAYS|^PASS_MIN_DAYS|^PASS_WARN_AGE' /etc/login.defs 2>/dev/null": "PASS_MAX_DAYS\t365",
		"grep -rE 'NOPASSWD' /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -v '^#'": "",
	}}

	c := auth.New()
	findings, err := c.Run(ctx, col)
	if err != nil {
		t.Fatal(err)
	}

	for _, f := range findings {
		if f.Severity >= audit.SeverityFail {
			t.Errorf("clean system should have no FAILs, got %s for %s", f.Severity, f.ID)
		}
	}
}

func TestAuth_MultipleUID0(t *testing.T) {
	ctx := factsCtx([]audit.UserFact{
		{Name: "root", UID: "0", Shell: "/bin/bash"},
		{Name: "toor", UID: "0", Shell: "/bin/bash"},
	})

	col := &mockCollector{commands: map[string]string{}}

	c := auth.New()
	findings, err := c.Run(ctx, col)
	if err != nil {
		t.Fatal(err)
	}

	for _, f := range findings {
		if f.ID == "auth-multiple-uid0" && f.Severity != audit.SeverityCritical {
			t.Errorf("multiple UID 0 should be CRITICAL, got %s", f.Severity)
		}
	}
}
