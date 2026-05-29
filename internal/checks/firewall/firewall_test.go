package firewall_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/Siovos/siovos-audit/internal/checks/firewall"
	"github.com/Siovos/siovos-audit/pkg/audit"
	"github.com/Siovos/siovos-audit/pkg/collector"
)

type mockCollector struct {
	commands map[string]string
	errors   map[string]error
}

func (m *mockCollector) Exec(_ context.Context, cmd string) ([]byte, error) {
	if err, ok := m.errors[cmd]; ok {
		return nil, err
	}
	if out, ok := m.commands[cmd]; ok {
		return []byte(out), nil
	}
	return nil, fmt.Errorf("command not found: %s", cmd)
}
func (m *mockCollector) ReadFile(_ context.Context, path string) ([]byte, error) {
	return nil, fmt.Errorf("not implemented")
}
func (m *mockCollector) Platform() collector.Platform { return collector.Platform{OS: "linux"} }
func (m *mockCollector) Target() string               { return "test" }
func (m *mockCollector) Close() error                  { return nil }

func TestFirewall_UFWActive(t *testing.T) {
	col := &mockCollector{commands: map[string]string{
		"ufw status 2>/dev/null || iptables -L -n 2>/dev/null | head -5": "Status: active\nTo                         Action      From\n--                         ------      ----\n22/tcp                     ALLOW       Anywhere",
		"ufw status verbose 2>/dev/null": "Status: active\nDefault: deny (incoming), allow (outgoing), disabled (routed)",
		"ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null": "State    Recv-Q   Send-Q     Local Address:Port     Peer Address:Port\nLISTEN   0        128              0.0.0.0:22            0.0.0.0:*",
	}}

	c := firewall.New()
	findings, err := c.Run(context.Background(), col)
	if err != nil {
		t.Fatal(err)
	}

	hasPassed := false
	for _, f := range findings {
		if f.ID == "firewall-active" && f.Severity == audit.SeverityPass {
			hasPassed = true
		}
		if f.ID == "firewall-default-deny" && f.Severity != audit.SeverityPass {
			t.Errorf("default deny should be PASS, got %s", f.Severity)
		}
	}
	if !hasPassed {
		t.Error("expected firewall-active to PASS")
	}
}

func TestFirewall_NoFirewall(t *testing.T) {
	col := &mockCollector{
		commands: map[string]string{},
		errors: map[string]error{
			"ufw status 2>/dev/null || iptables -L -n 2>/dev/null | head -5": fmt.Errorf("command not found"),
		},
	}

	c := firewall.New()
	findings, err := c.Run(context.Background(), col)
	if err != nil {
		t.Fatal(err)
	}

	for _, f := range findings {
		if f.ID == "firewall-active" && f.Severity != audit.SeverityFail {
			t.Errorf("no firewall should be FAIL, got %s", f.Severity)
		}
	}
}

func TestFirewall_UnexpectedPorts(t *testing.T) {
	col := &mockCollector{commands: map[string]string{
		"ufw status 2>/dev/null || iptables -L -n 2>/dev/null | head -5": "Status: active",
		"ufw status verbose 2>/dev/null": "Status: active\nDefault: deny (incoming)",
		"ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null": "State    Recv-Q   Send-Q     Local Address:Port     Peer Address:Port\nLISTEN   0        128              0.0.0.0:22            0.0.0.0:*\nLISTEN   0        128              0.0.0.0:3000          0.0.0.0:*\nLISTEN   0        128              0.0.0.0:6379          0.0.0.0:*",
	}}

	c := firewall.New()
	findings, err := c.Run(context.Background(), col)
	if err != nil {
		t.Fatal(err)
	}

	foundWarn := false
	for _, f := range findings {
		if f.ID == "firewall-open-port-3000" && f.Severity == audit.SeverityWarn {
			foundWarn = true
		}
	}
	if !foundWarn {
		t.Error("expected warning for port 3000")
	}
}
