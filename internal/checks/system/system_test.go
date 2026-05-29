package system_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/Siovos/siovos-audit/internal/checks/system"
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
	return nil, fmt.Errorf("command not found")
}
func (m *mockCollector) ReadFile(_ context.Context, _ string) ([]byte, error) {
	return nil, fmt.Errorf("not implemented")
}
func (m *mockCollector) Platform() collector.Platform { return collector.Platform{OS: "linux"} }
func (m *mockCollector) Target() string               { return "test" }
func (m *mockCollector) Close() error                  { return nil }

func TestSystem_NoUpdates(t *testing.T) {
	col := &mockCollector{commands: map[string]string{
		"apt list --upgradable 2>/dev/null | grep -i security | wc -l": "0",
		"dpkg -l unattended-upgrades 2>/dev/null | grep '^ii'":         "ii  unattended-upgrades  2.9.1",
		"cat /etc/apt/apt.conf.d/20auto-upgrades 2>/dev/null":          `APT::Periodic::Unattended-Upgrade "1";`,
		"stat -c '%a' /etc/shadow 2>/dev/null":                         "640",
		"stat -c '%a' /etc/gshadow 2>/dev/null":                        "640",
		"stat -c '%a' /etc/passwd 2>/dev/null":                         "644",
		"stat -c '%a' /root/.ssh 2>/dev/null":                          "700",
		"sysctl -n net.ipv4.conf.all.rp_filter 2>/dev/null":           "1",
		"sysctl -n net.ipv4.conf.all.accept_redirects 2>/dev/null":    "0",
		"sysctl -n net.ipv4.conf.all.send_redirects 2>/dev/null":      "0",
		"sysctl -n kernel.randomize_va_space 2>/dev/null":              "2",
	}}

	c := system.New()
	findings, err := c.Run(context.Background(), col)
	if err != nil {
		t.Fatal(err)
	}

	for _, f := range findings {
		if f.Severity >= audit.SeverityFail {
			t.Errorf("hardened system should have no FAILs, got %s for %s", f.Severity, f.ID)
		}
	}
}

func TestSystem_PermissionsTooOpen(t *testing.T) {
	col := &mockCollector{commands: map[string]string{
		"apt list --upgradable 2>/dev/null | grep -i security | wc -l": "0",
		"stat -c '%a' /etc/shadow 2>/dev/null":                         "777",
		"stat -c '%a' /etc/passwd 2>/dev/null":                         "666",
		"sysctl -n kernel.randomize_va_space 2>/dev/null":              "0",
	}}

	c := system.New()
	findings, err := c.Run(context.Background(), col)
	if err != nil {
		t.Fatal(err)
	}

	hasFail := false
	for _, f := range findings {
		if f.ID == "system-perms-etc-shadow" && f.Severity == audit.SeverityFail {
			hasFail = true
		}
	}
	if !hasFail {
		t.Error("shadow 777 should be FAIL")
	}
}
