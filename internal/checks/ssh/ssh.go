package ssh

import (
	"context"
	"strings"

	"github.com/Siovos/siovos-audit/pkg/audit"
	"github.com/Siovos/siovos-audit/pkg/collector"
)

type Check struct{}

func New() *Check { return &Check{} }

func (c *Check) ID() string       { return "ssh" }
func (c *Check) Name() string     { return "SSH Security" }
func (c *Check) Category() string { return "ssh" }

func (c *Check) Run(ctx context.Context, col collector.Collector) ([]audit.Finding, error) {
	data, err := col.ReadFile(ctx, "/etc/ssh/sshd_config")
	if err != nil {
		return nil, err
	}
	config := string(data)

	var findings []audit.Finding

	findings = append(findings, checkPasswordAuth(config))
	findings = append(findings, checkRootLogin(config))
	findings = append(findings, checkPermitEmptyPasswords(config))
	findings = append(findings, checkProtocol(config))

	return findings, nil
}

func checkPasswordAuth(config string) audit.Finding {
	f := audit.Finding{
		ID:      "ssh-password-auth",
		CheckID: "ssh",
		Title:   "Password authentication",
	}

	val := getSSHConfigValue(config, "PasswordAuthentication")
	switch strings.ToLower(val) {
	case "no":
		f.Severity = audit.SeverityPass
		f.Title = "Password authentication disabled"
	case "yes", "":
		f.Severity = audit.SeverityFail
		f.Title = "Password authentication enabled"
		f.Remediation = "Set 'PasswordAuthentication no' in /etc/ssh/sshd_config"
		f.References = []string{"CIS 5.2.10"}
	}
	f.Evidence = "PasswordAuthentication=" + val

	return f
}

func checkRootLogin(config string) audit.Finding {
	f := audit.Finding{
		ID:      "ssh-root-login",
		CheckID: "ssh",
		Title:   "Root login",
	}

	val := getSSHConfigValue(config, "PermitRootLogin")
	switch strings.ToLower(val) {
	case "no":
		f.Severity = audit.SeverityPass
		f.Title = "Root login disabled"
	case "prohibit-password", "without-password", "forced-commands-only":
		f.Severity = audit.SeverityInfo
		f.Title = "Root login via key only"
	case "yes", "":
		f.Severity = audit.SeverityFail
		f.Title = "Root login with password allowed"
		f.Remediation = "Set 'PermitRootLogin no' or 'PermitRootLogin prohibit-password' in /etc/ssh/sshd_config"
		f.References = []string{"CIS 5.2.8"}
	}
	f.Evidence = "PermitRootLogin=" + val

	return f
}

func checkPermitEmptyPasswords(config string) audit.Finding {
	f := audit.Finding{
		ID:      "ssh-empty-passwords",
		CheckID: "ssh",
		Title:   "Empty passwords",
	}

	val := getSSHConfigValue(config, "PermitEmptyPasswords")
	switch strings.ToLower(val) {
	case "no", "":
		f.Severity = audit.SeverityPass
		f.Title = "Empty passwords not permitted"
	case "yes":
		f.Severity = audit.SeverityCritical
		f.Title = "Empty passwords permitted"
		f.Remediation = "Set 'PermitEmptyPasswords no' in /etc/ssh/sshd_config"
		f.References = []string{"CIS 5.2.11"}
	}
	f.Evidence = "PermitEmptyPasswords=" + val

	return f
}

func checkProtocol(config string) audit.Finding {
	f := audit.Finding{
		ID:      "ssh-protocol",
		CheckID: "ssh",
		Title:   "SSH protocol version",
	}

	val := getSSHConfigValue(config, "Protocol")
	switch val {
	case "2", "":
		f.Severity = audit.SeverityPass
		f.Title = "SSH Protocol 2 (default)"
	default:
		f.Severity = audit.SeverityFail
		f.Title = "SSH Protocol version is not 2"
		f.Remediation = "Set 'Protocol 2' in /etc/ssh/sshd_config"
		f.References = []string{"CIS 5.2.1"}
	}
	f.Evidence = "Protocol=" + val

	return f
}

func getSSHConfigValue(config, key string) string {
	for _, line := range strings.Split(config, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) >= 2 && strings.EqualFold(parts[0], key) {
			return parts[1]
		}
	}
	return ""
}
