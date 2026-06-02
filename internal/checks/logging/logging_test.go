package logging_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/Siovos/siovos-audit/internal/checks/logging"
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

func TestLogging_AllActive(t *testing.T) {
	col := &mockCollector{commands: map[string]string{
		"systemctl is-active rsyslog 2>/dev/null || systemctl is-active systemd-journald 2>/dev/null || systemctl is-active syslog-ng 2>/dev/null": "active",
		"systemctl is-active auditd 2>/dev/null": "active",
		"auditctl -l 2>/dev/null | wc -l":        "15",
		"test -f /etc/logrotate.conf && echo found 2>/dev/null": "found",
		"test -f /var/log/auth.log && stat -c '%a' /var/log/auth.log 2>/dev/null": "640",
		"grep -rE '^[^#]*@@' /etc/rsyslog.conf /etc/rsyslog.d/ 2>/dev/null": "*.* @@logserver:514",
	}}

	c := logging.New()
	findings, err := c.Run(context.Background(), col)
	if err != nil {
		t.Fatal(err)
	}

	for _, f := range findings {
		if f.Severity >= audit.SeverityFail {
			t.Errorf("all-active system should have no FAILs, got %s for %s", f.Severity, f.ID)
		}
	}
}

func TestLogging_NothingActive(t *testing.T) {
	col := &mockCollector{commands: map[string]string{}}

	c := logging.New()
	findings, err := c.Run(context.Background(), col)
	if err != nil {
		t.Fatal(err)
	}

	hasFail := false
	for _, f := range findings {
		if f.ID == "logging-syslog" && f.Severity == audit.SeverityFail {
			hasFail = true
		}
	}
	if !hasFail {
		t.Error("no syslog should be FAIL")
	}
}
