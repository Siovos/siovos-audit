package vpn_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/Siovos/siovos-audit/internal/checks/vpn"
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

func TestVPN_NotDetected(t *testing.T) {
	col := &mockCollector{commands: map[string]string{}}

	c := vpn.New()
	findings, err := c.Run(context.Background(), col)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].Severity != audit.SeverityInfo {
		t.Error("expected single INFO finding when WireGuard not detected")
	}
}

func TestVPN_ActiveWithGoodConfig(t *testing.T) {
	col := &mockCollector{commands: map[string]string{
		"wg show 2>/dev/null":                        "interface: wg0\n  public key: abc123\n  listening port: 51820",
		"wg show interfaces 2>/dev/null":             "wg0",
		"wg show all latest-handshakes 2>/dev/null":  "wg0\tabc12345\t1716000000",
		"stat -c '%a %n' /etc/wireguard/*.conf 2>/dev/null": "600 /etc/wireguard/wg0.conf",
	}}

	c := vpn.New()
	findings, err := c.Run(context.Background(), col)
	if err != nil {
		t.Fatal(err)
	}

	for _, f := range findings {
		if f.Severity >= audit.SeverityFail {
			t.Errorf("good VPN config should have no FAILs, got %s for %s", f.Severity, f.ID)
		}
	}
}

func TestVPN_PermissivConfig(t *testing.T) {
	col := &mockCollector{commands: map[string]string{
		"wg show 2>/dev/null":                        "interface: wg0",
		"wg show interfaces 2>/dev/null":             "wg0",
		"wg show all latest-handshakes 2>/dev/null":  "",
		"stat -c '%a %n' /etc/wireguard/*.conf 2>/dev/null": "644 /etc/wireguard/wg0.conf",
	}}

	c := vpn.New()
	findings, err := c.Run(context.Background(), col)
	if err != nil {
		t.Fatal(err)
	}

	hasFail := false
	for _, f := range findings {
		if f.Severity == audit.SeverityFail {
			hasFail = true
		}
	}
	if !hasFail {
		t.Error("644 config should produce a FAIL")
	}
}
