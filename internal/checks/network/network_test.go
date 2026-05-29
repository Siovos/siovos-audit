package network_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/Siovos/siovos-audit/internal/checks/network"
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
	return nil, fmt.Errorf("command not found")
}
func (m *mockCollector) ReadFile(_ context.Context, path string) ([]byte, error) {
	if content, ok := m.files[path]; ok {
		return []byte(content), nil
	}
	return nil, fmt.Errorf("file not found")
}
func (m *mockCollector) Platform() collector.Platform { return collector.Platform{OS: "linux"} }
func (m *mockCollector) Target() string               { return "test" }
func (m *mockCollector) Close() error                  { return nil }

func TestNetwork_DNSConfigured(t *testing.T) {
	col := &mockCollector{
		commands: map[string]string{
			"sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null":                "1",
			"ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null": "State\nLISTEN 0 128 0.0.0.0:22 0.0.0.0:*\nLISTEN 0 128 127.0.0.1:5432 0.0.0.0:*",
		},
		files: map[string]string{
			"/etc/resolv.conf": "nameserver 1.1.1.1\nnameserver 8.8.8.8\n",
		},
	}

	c := network.New()
	findings, err := c.Run(context.Background(), col)
	if err != nil {
		t.Fatal(err)
	}

	for _, f := range findings {
		if f.ID == "network-dns" && f.Severity != audit.SeverityPass {
			t.Errorf("DNS should be PASS, got %s", f.Severity)
		}
		if f.ID == "network-ipv6" && f.Severity != audit.SeverityPass {
			t.Errorf("IPv6 disabled should be PASS, got %s", f.Severity)
		}
	}
}

func TestNetwork_NoDNS(t *testing.T) {
	col := &mockCollector{
		commands: map[string]string{},
		files: map[string]string{
			"/etc/resolv.conf": "# empty\n",
		},
	}

	c := network.New()
	findings, err := c.Run(context.Background(), col)
	if err != nil {
		t.Fatal(err)
	}

	for _, f := range findings {
		if f.ID == "network-dns" && f.Severity != audit.SeverityWarn {
			t.Errorf("no DNS should be WARN, got %s", f.Severity)
		}
	}
}
