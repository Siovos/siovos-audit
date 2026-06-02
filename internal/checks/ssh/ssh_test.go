package ssh_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/Siovos/siovos-audit/internal/checks/ssh"
	"github.com/Siovos/siovos-audit/pkg/audit"
	"github.com/Siovos/siovos-audit/pkg/collector"
)

type mockCollector struct {
	files    map[string]string
	commands map[string]string
}

func (m *mockCollector) Exec(_ context.Context, cmd string) ([]byte, error) {
	if m.commands != nil {
		if out, ok := m.commands[cmd]; ok {
			return []byte(out), nil
		}
	}
	return nil, fmt.Errorf("command not found: %s", cmd)
}
func (m *mockCollector) ReadFile(_ context.Context, path string) ([]byte, error) {
	if content, ok := m.files[path]; ok {
		return []byte(content), nil
	}
	return nil, fmt.Errorf("file not found: %s", path)
}
func (m *mockCollector) Platform() collector.Platform { return collector.Platform{OS: "linux"} }
func (m *mockCollector) Target() string               { return "test" }
func (m *mockCollector) Close() error                  { return nil }

func TestSSH_HardenedConfig(t *testing.T) {
	col := &mockCollector{
		files: map[string]string{
			"/etc/ssh/sshd_config": `
Port 22
PasswordAuthentication no
PermitRootLogin no
PermitEmptyPasswords no
Protocol 2
MaxAuthTries 3
ClientAliveInterval 300
ClientAliveCountMax 3
X11Forwarding no
AllowTcpForwarding no
Banner /etc/issue.net
StrictModes yes
UsePAM yes
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org
`,
		},
		commands: map[string]string{
			"stat -c '%a' /etc/ssh/sshd_config 2>/dev/null":       "600",
			"stat -c '%a' /root/.ssh/authorized_keys 2>/dev/null": "600",
		},
	}

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
	col := &mockCollector{
		files: map[string]string{
			"/etc/ssh/sshd_config": `
PasswordAuthentication yes
PermitRootLogin yes
PermitEmptyPasswords yes
Protocol 1
Ciphers aes128-cbc,3des-cbc
MACs hmac-md5
KexAlgorithms diffie-hellman-group1-sha1
StrictModes no
`,
		},
		commands: map[string]string{
			"stat -c '%a' /etc/ssh/sshd_config 2>/dev/null": "777",
		},
	}

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
	if severities["ssh-ciphers"] != audit.SeverityFail {
		t.Error("weak ciphers should be FAIL")
	}
	if severities["ssh-macs"] != audit.SeverityFail {
		t.Error("weak MACs should be FAIL")
	}
	if severities["ssh-kex"] != audit.SeverityFail {
		t.Error("weak kex should be FAIL")
	}
	if severities["ssh-strict-modes"] != audit.SeverityFail {
		t.Error("StrictModes no should be FAIL")
	}
	if severities["ssh-config-perms"] != audit.SeverityFail {
		t.Error("config perms 777 should be FAIL")
	}
}

func TestSSH_DefaultConfig(t *testing.T) {
	col := &mockCollector{
		files: map[string]string{
			"/etc/ssh/sshd_config": `
# Default config with only comments
#PasswordAuthentication yes
`,
		},
		commands: map[string]string{},
	}

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
	col := &mockCollector{
		files: map[string]string{
			"/etc/ssh/sshd_config": `PermitRootLogin prohibit-password`,
		},
		commands: map[string]string{},
	}

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
