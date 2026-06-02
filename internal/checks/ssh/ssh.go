package ssh

import (
	"context"
	"fmt"
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

	// Core checks
	findings = append(findings, checkPasswordAuth(config))
	findings = append(findings, checkRootLogin(config))
	findings = append(findings, checkPermitEmptyPasswords(config))
	findings = append(findings, checkProtocol(config))

	// Access control
	findings = append(findings, checkMaxAuthTries(config))
	findings = append(findings, checkLoginGraceTime(config))
	findings = append(findings, checkAllowUsers(config))

	// Forwarding
	findings = append(findings, checkX11Forwarding(config))
	findings = append(findings, checkTCPForwarding(config))

	// Session
	findings = append(findings, checkClientAlive(config))
	findings = append(findings, checkBanner(config))
	findings = append(findings, checkUsePAM(config))
	findings = append(findings, checkStrictModes(config))

	// Crypto
	findings = append(findings, checkCiphers(config))
	findings = append(findings, checkMACs(config))
	findings = append(findings, checkKexAlgorithms(config))
	findings = append(findings, checkHostKeyAlgorithms(config))

	// File permissions
	findings = append(findings, checkConfigPermissions(ctx, col)...)

	return findings, nil
}

func checkPasswordAuth(config string) audit.Finding {
	f := audit.Finding{ID: "ssh-password-auth", CheckID: "ssh"}
	val := getSSHConfigValue(config, "PasswordAuthentication")
	switch strings.ToLower(val) {
	case "no":
		f.Severity = audit.SeverityPass
		f.Title = "Password authentication disabled"
	default:
		f.Severity = audit.SeverityFail
		f.Title = "Password authentication enabled"
		f.Remediation = "Set 'PasswordAuthentication no' in /etc/ssh/sshd_config"
		f.References = []string{"CIS 5.2.10"}
	}
	f.Evidence = "PasswordAuthentication=" + val
	return f
}

func checkRootLogin(config string) audit.Finding {
	f := audit.Finding{ID: "ssh-root-login", CheckID: "ssh"}
	val := getSSHConfigValue(config, "PermitRootLogin")
	switch strings.ToLower(val) {
	case "no":
		f.Severity = audit.SeverityPass
		f.Title = "Root login disabled"
	case "prohibit-password", "without-password", "forced-commands-only":
		f.Severity = audit.SeverityInfo
		f.Title = "Root login via key only"
	default:
		f.Severity = audit.SeverityFail
		f.Title = "Root login with password allowed"
		f.Remediation = "Set 'PermitRootLogin no' or 'PermitRootLogin prohibit-password' in /etc/ssh/sshd_config"
		f.References = []string{"CIS 5.2.8"}
	}
	f.Evidence = "PermitRootLogin=" + val
	return f
}

func checkPermitEmptyPasswords(config string) audit.Finding {
	f := audit.Finding{ID: "ssh-empty-passwords", CheckID: "ssh"}
	val := getSSHConfigValue(config, "PermitEmptyPasswords")
	switch strings.ToLower(val) {
	case "no", "":
		f.Severity = audit.SeverityPass
		f.Title = "Empty passwords not permitted"
	default:
		f.Severity = audit.SeverityCritical
		f.Title = "Empty passwords permitted"
		f.Remediation = "Set 'PermitEmptyPasswords no' in /etc/ssh/sshd_config"
		f.References = []string{"CIS 5.2.11"}
	}
	f.Evidence = "PermitEmptyPasswords=" + val
	return f
}

func checkProtocol(config string) audit.Finding {
	f := audit.Finding{ID: "ssh-protocol", CheckID: "ssh"}
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

func checkMaxAuthTries(config string) audit.Finding {
	f := audit.Finding{ID: "ssh-max-auth-tries", CheckID: "ssh"}
	val := getSSHConfigValue(config, "MaxAuthTries")
	switch {
	case val == "" || val == "6":
		f.Severity = audit.SeverityWarn
		f.Title = "MaxAuthTries at default (6)"
		f.Remediation = "Set 'MaxAuthTries 3' to limit brute force attempts"
		f.References = []string{"CIS 5.2.5"}
	case val <= "4":
		f.Severity = audit.SeverityPass
		f.Title = fmt.Sprintf("MaxAuthTries set to %s", val)
	default:
		f.Severity = audit.SeverityWarn
		f.Title = fmt.Sprintf("MaxAuthTries too high (%s)", val)
		f.Remediation = "Set 'MaxAuthTries 3' in /etc/ssh/sshd_config"
	}
	f.Evidence = "MaxAuthTries=" + val
	return f
}

func checkLoginGraceTime(config string) audit.Finding {
	f := audit.Finding{ID: "ssh-login-grace-time", CheckID: "ssh"}
	val := getSSHConfigValue(config, "LoginGraceTime")
	switch {
	case val == "":
		f.Severity = audit.SeverityInfo
		f.Title = "LoginGraceTime at default (120s)"
	case val == "0":
		f.Severity = audit.SeverityFail
		f.Title = "LoginGraceTime disabled (unlimited)"
		f.Remediation = "Set 'LoginGraceTime 60' in /etc/ssh/sshd_config"
		f.References = []string{"CIS 5.2.14"}
	default:
		f.Severity = audit.SeverityPass
		f.Title = fmt.Sprintf("LoginGraceTime set to %s", val)
	}
	f.Evidence = "LoginGraceTime=" + val
	return f
}

func checkAllowUsers(config string) audit.Finding {
	f := audit.Finding{ID: "ssh-allow-users", CheckID: "ssh"}
	users := getSSHConfigValue(config, "AllowUsers")
	groups := getSSHConfigValue(config, "AllowGroups")
	if users != "" || groups != "" {
		f.Severity = audit.SeverityPass
		f.Title = "SSH access restricted"
		if users != "" {
			f.Evidence = "AllowUsers=" + users
		}
		if groups != "" {
			f.Evidence += " AllowGroups=" + groups
		}
	} else {
		f.Severity = audit.SeverityInfo
		f.Title = "No AllowUsers/AllowGroups restriction"
		f.Evidence = "Any valid user can attempt SSH login"
	}
	return f
}

func checkX11Forwarding(config string) audit.Finding {
	f := audit.Finding{ID: "ssh-x11-forwarding", CheckID: "ssh"}
	val := getSSHConfigValue(config, "X11Forwarding")
	switch strings.ToLower(val) {
	case "no":
		f.Severity = audit.SeverityPass
		f.Title = "X11 forwarding disabled"
	case "yes":
		f.Severity = audit.SeverityWarn
		f.Title = "X11 forwarding enabled"
		f.Remediation = "Set 'X11Forwarding no' unless required"
		f.References = []string{"CIS 5.2.6"}
	default:
		f.Severity = audit.SeverityInfo
		f.Title = "X11 forwarding at default"
	}
	f.Evidence = "X11Forwarding=" + val
	return f
}

func checkTCPForwarding(config string) audit.Finding {
	f := audit.Finding{ID: "ssh-tcp-forwarding", CheckID: "ssh"}
	val := getSSHConfigValue(config, "AllowTcpForwarding")
	switch strings.ToLower(val) {
	case "no":
		f.Severity = audit.SeverityPass
		f.Title = "TCP forwarding disabled"
	case "yes", "":
		f.Severity = audit.SeverityInfo
		f.Title = "TCP forwarding allowed"
		f.Evidence = "AllowTcpForwarding=" + val
	default:
		f.Severity = audit.SeverityPass
		f.Title = fmt.Sprintf("TCP forwarding: %s", val)
	}
	f.Evidence = "AllowTcpForwarding=" + val
	return f
}

func checkClientAlive(config string) audit.Finding {
	f := audit.Finding{ID: "ssh-client-alive", CheckID: "ssh"}
	interval := getSSHConfigValue(config, "ClientAliveInterval")
	countMax := getSSHConfigValue(config, "ClientAliveCountMax")
	if interval != "" && interval != "0" {
		f.Severity = audit.SeverityPass
		f.Title = fmt.Sprintf("Client alive: interval=%s, max=%s", interval, countMax)
	} else {
		f.Severity = audit.SeverityWarn
		f.Title = "No client alive interval set (idle sessions stay open)"
		f.Remediation = "Set 'ClientAliveInterval 300' and 'ClientAliveCountMax 3' in /etc/ssh/sshd_config"
		f.References = []string{"CIS 5.2.13"}
	}
	f.Evidence = fmt.Sprintf("ClientAliveInterval=%s ClientAliveCountMax=%s", interval, countMax)
	return f
}

func checkBanner(config string) audit.Finding {
	f := audit.Finding{ID: "ssh-banner", CheckID: "ssh"}
	val := getSSHConfigValue(config, "Banner")
	if val != "" && val != "none" {
		f.Severity = audit.SeverityPass
		f.Title = "SSH warning banner configured"
		f.Evidence = "Banner=" + val
	} else {
		f.Severity = audit.SeverityInfo
		f.Title = "No SSH warning banner"
		f.Evidence = "Banner not set"
	}
	return f
}

func checkUsePAM(config string) audit.Finding {
	f := audit.Finding{ID: "ssh-use-pam", CheckID: "ssh"}
	val := getSSHConfigValue(config, "UsePAM")
	switch strings.ToLower(val) {
	case "yes", "":
		f.Severity = audit.SeverityPass
		f.Title = "PAM authentication enabled"
	case "no":
		f.Severity = audit.SeverityInfo
		f.Title = "PAM authentication disabled"
	}
	f.Evidence = "UsePAM=" + val
	return f
}

func checkStrictModes(config string) audit.Finding {
	f := audit.Finding{ID: "ssh-strict-modes", CheckID: "ssh"}
	val := getSSHConfigValue(config, "StrictModes")
	switch strings.ToLower(val) {
	case "yes", "":
		f.Severity = audit.SeverityPass
		f.Title = "StrictModes enabled (checks file permissions)"
	case "no":
		f.Severity = audit.SeverityFail
		f.Title = "StrictModes disabled"
		f.Remediation = "Set 'StrictModes yes' in /etc/ssh/sshd_config"
	}
	f.Evidence = "StrictModes=" + val
	return f
}

var weakCiphers = []string{"3des-cbc", "aes128-cbc", "aes192-cbc", "aes256-cbc", "blowfish-cbc", "cast128-cbc", "arcfour"}

func checkCiphers(config string) audit.Finding {
	f := audit.Finding{ID: "ssh-ciphers", CheckID: "ssh"}
	val := getSSHConfigValue(config, "Ciphers")
	if val == "" {
		f.Severity = audit.SeverityInfo
		f.Title = "Ciphers at default (OS-dependent)"
		f.Evidence = "Ciphers not explicitly set"
		return f
	}
	found := findWeakValues(val, weakCiphers)
	if len(found) > 0 {
		f.Severity = audit.SeverityFail
		f.Title = fmt.Sprintf("Weak SSH ciphers: %s", strings.Join(found, ", "))
		f.Remediation = "Remove weak ciphers. Use: Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com"
		f.References = []string{"CIS 5.2.13"}
	} else {
		f.Severity = audit.SeverityPass
		f.Title = "SSH ciphers are strong"
	}
	f.Evidence = "Ciphers=" + val
	return f
}

var weakMACs = []string{"hmac-md5", "hmac-md5-96", "hmac-sha1-96", "hmac-md5-etm@openssh.com", "hmac-md5-96-etm@openssh.com"}

func checkMACs(config string) audit.Finding {
	f := audit.Finding{ID: "ssh-macs", CheckID: "ssh"}
	val := getSSHConfigValue(config, "MACs")
	if val == "" {
		f.Severity = audit.SeverityInfo
		f.Title = "MACs at default (OS-dependent)"
		f.Evidence = "MACs not explicitly set"
		return f
	}
	found := findWeakValues(val, weakMACs)
	if len(found) > 0 {
		f.Severity = audit.SeverityFail
		f.Title = fmt.Sprintf("Weak SSH MACs: %s", strings.Join(found, ", "))
		f.Remediation = "Remove weak MACs. Use: MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com"
	} else {
		f.Severity = audit.SeverityPass
		f.Title = "SSH MACs are strong"
	}
	f.Evidence = "MACs=" + val
	return f
}

var weakKex = []string{"diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1", "diffie-hellman-group-exchange-sha1"}

func checkKexAlgorithms(config string) audit.Finding {
	f := audit.Finding{ID: "ssh-kex", CheckID: "ssh"}
	val := getSSHConfigValue(config, "KexAlgorithms")
	if val == "" {
		f.Severity = audit.SeverityInfo
		f.Title = "KexAlgorithms at default (OS-dependent)"
		f.Evidence = "KexAlgorithms not explicitly set"
		return f
	}
	found := findWeakValues(val, weakKex)
	if len(found) > 0 {
		f.Severity = audit.SeverityFail
		f.Title = fmt.Sprintf("Weak key exchange: %s", strings.Join(found, ", "))
		f.Remediation = "Remove weak kex. Use: KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org"
	} else {
		f.Severity = audit.SeverityPass
		f.Title = "Key exchange algorithms are strong"
	}
	f.Evidence = "KexAlgorithms=" + val
	return f
}

func checkHostKeyAlgorithms(config string) audit.Finding {
	f := audit.Finding{ID: "ssh-host-key-alg", CheckID: "ssh"}
	val := getSSHConfigValue(config, "HostKeyAlgorithms")
	if val == "" {
		f.Severity = audit.SeverityInfo
		f.Title = "HostKeyAlgorithms at default"
		f.Evidence = "HostKeyAlgorithms not explicitly set"
		return f
	}
	if strings.Contains(val, "ssh-dss") {
		f.Severity = audit.SeverityFail
		f.Title = "DSA host key algorithm enabled (insecure)"
		f.Remediation = "Remove ssh-dss from HostKeyAlgorithms"
	} else {
		f.Severity = audit.SeverityPass
		f.Title = "Host key algorithms are strong"
	}
	f.Evidence = "HostKeyAlgorithms=" + val
	return f
}

func checkConfigPermissions(ctx context.Context, col collector.Collector) []audit.Finding {
	var findings []audit.Finding

	// sshd_config permissions
	out, err := col.Exec(ctx, "stat -c '%a' /etc/ssh/sshd_config 2>/dev/null")
	if err == nil {
		perms := strings.TrimSpace(string(out))
		if perms == "600" || perms == "644" {
			findings = append(findings, audit.Finding{
				ID: "ssh-config-perms", CheckID: "ssh",
				Severity: audit.SeverityPass,
				Title:    fmt.Sprintf("sshd_config permissions OK (%s)", perms),
			})
		} else {
			findings = append(findings, audit.Finding{
				ID: "ssh-config-perms", CheckID: "ssh",
				Severity:    audit.SeverityFail,
				Title:       fmt.Sprintf("sshd_config permissions too open (%s)", perms),
				Remediation: "chmod 600 /etc/ssh/sshd_config",
			})
		}
	}

	// authorized_keys permissions
	out, err = col.Exec(ctx, "stat -c '%a' /root/.ssh/authorized_keys 2>/dev/null")
	if err == nil {
		perms := strings.TrimSpace(string(out))
		if perms == "600" || perms == "644" || perms == "400" {
			findings = append(findings, audit.Finding{
				ID: "ssh-authkeys-perms", CheckID: "ssh",
				Severity: audit.SeverityPass,
				Title:    fmt.Sprintf("authorized_keys permissions OK (%s)", perms),
			})
		} else {
			findings = append(findings, audit.Finding{
				ID: "ssh-authkeys-perms", CheckID: "ssh",
				Severity:    audit.SeverityFail,
				Title:       fmt.Sprintf("authorized_keys permissions too open (%s)", perms),
				Remediation: "chmod 600 /root/.ssh/authorized_keys",
			})
		}
	}

	return findings
}

func findWeakValues(configured string, weakList []string) []string {
	var found []string
	for _, weak := range weakList {
		if strings.Contains(strings.ToLower(configured), strings.ToLower(weak)) {
			found = append(found, weak)
		}
	}
	return found
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
