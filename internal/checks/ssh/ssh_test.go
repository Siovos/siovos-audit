package ssh_test

import (
	"context"
	"testing"

	"github.com/Siovos/siovos-audit/internal/checks/ssh"
	"github.com/Siovos/siovos-audit/pkg/audit"
	"github.com/Siovos/siovos-audit/pkg/collector"
)

type mockCollector struct {
	files map[string]string
}

func (m *mockCollector) Exec(_ context.Context, cmd string) ([]byte, error) { return nil, nil }
func (m *mockCollector) ReadFile(_ context.Context, path string) ([]byte, error) {
	if content, ok := m.files[path]; ok {
		return []byte(content), nil
	}
	return nil, &mockError{msg: "file not found: " + path}
}
func (m *mockCollector) Platform() collector.Platform { return collector.Platform{OS: "linux"} }
func (m *mockCollector) Target() string               { return "test" }
func (m *mockCollector) Close() error                  { return nil }

type mockError struct{ msg string }

func (e *mockError) Error() string { return e.msg }

func TestSSH_HardenedConfig(t *testing.T) {
	col := &mockCollector{files: map[string]string{
		"/etc/ssh/sshd_config": `
Port 22
PasswordAuthentication no
PermitRootLogin no
PermitEmptyPasswords no
Protocol 2
`,
	}}

	c := ssh.New()
	findings, err := c.Run(context.Background(), col)
	if err != nil {
		t.Fatal(err)
	}

	for _, f := range findings {
		if f.Severity > audit.SeverityInfo {
			t.Errorf("expected all PASS/INFO on hardened config, got %s for %s", f.Severity, f.ID)
		}
	}
}

func TestSSH_WeakConfig(t *testing.T) {
	col := &mockCollector{files: map[string]string{
		"/etc/ssh/sshd_config": `
PasswordAuthentication yes
PermitRootLogin yes
PermitEmptyPasswords yes
Protocol 1
`,
	}}

	c := ssh.New()
	findings, err := c.Run(context.Background(), col)
	if err != nil {
		t.Fatal(err)
	}

	severities := make(map[string]audit.Severity)
	for _, f := range findings {
		severities[f.ID] = f.Severity
	}

	if severities["ssh-password-auth"] != audit.SeverityFail {
		t.Error("password auth yes should be FAIL")
	}
	if severities["ssh-root-login"] != audit.SeverityFail {
		t.Error("root login yes should be FAIL")
	}
	if severities["ssh-empty-passwords"] != audit.SeverityCritical {
		t.Error("empty passwords yes should be CRITICAL")
	}
	if severities["ssh-protocol"] != audit.SeverityFail {
		t.Error("protocol 1 should be FAIL")
	}
}

func TestSSH_DefaultConfig(t *testing.T) {
	col := &mockCollector{files: map[string]string{
		"/etc/ssh/sshd_config": `
# Default config with only comments
#PasswordAuthentication yes
`,
	}}

	c := ssh.New()
	findings, err := c.Run(context.Background(), col)
	if err != nil {
		t.Fatal(err)
	}

	// Default values: PasswordAuth=yes (FAIL), RootLogin=yes (FAIL), EmptyPasswords=no (PASS), Protocol=2 (PASS)
	severities := make(map[string]audit.Severity)
	for _, f := range findings {
		severities[f.ID] = f.Severity
	}

	if severities["ssh-password-auth"] != audit.SeverityFail {
		t.Error("default password auth should be FAIL")
	}
	if severities["ssh-empty-passwords"] != audit.SeverityPass {
		t.Error("default empty passwords should be PASS")
	}
	if severities["ssh-protocol"] != audit.SeverityPass {
		t.Error("default protocol should be PASS")
	}
}

func TestSSH_RootLoginKeyOnly(t *testing.T) {
	col := &mockCollector{files: map[string]string{
		"/etc/ssh/sshd_config": `PermitRootLogin prohibit-password`,
	}}

	c := ssh.New()
	findings, err := c.Run(context.Background(), col)
	if err != nil {
		t.Fatal(err)
	}

	for _, f := range findings {
		if f.ID == "ssh-root-login" && f.Severity != audit.SeverityInfo {
			t.Errorf("prohibit-password should be INFO, got %s", f.Severity)
		}
	}
}
