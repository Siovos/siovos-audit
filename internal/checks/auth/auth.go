package auth

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/Siovos/siovos-audit/pkg/audit"
	"github.com/Siovos/siovos-audit/pkg/collector"
)

type Check struct{}

func New() *Check { return &Check{} }

func (c *Check) ID() string       { return "auth" }
func (c *Check) Name() string     { return "Authentication" }
func (c *Check) Category() string { return "auth" }

func (c *Check) Run(ctx context.Context, col collector.Collector) ([]audit.Finding, error) {
	facts := audit.GetFacts(ctx)

	var findings []audit.Finding
	findings = append(findings, checkMultipleUID0(facts)...)
	findings = append(findings, checkPasswordlessAccounts(ctx, col)...)
	findings = append(findings, checkSystemShells(facts)...)
	findings = append(findings, checkPasswordHashing(ctx, col)...)
	findings = append(findings, checkPasswordAging(ctx, col)...)
	findings = append(findings, checkSudoers(ctx, col)...)
	findings = append(findings, checkFailedLogins(ctx, col)...)

	return findings, nil
}

func checkMultipleUID0(facts *audit.Facts) []audit.Finding {
	if facts == nil {
		return nil
	}
	var roots []string
	for _, u := range facts.Users {
		if u.UID == "0" {
			roots = append(roots, u.Name)
		}
	}
	if len(roots) > 1 {
		return []audit.Finding{{
			ID: "auth-multiple-uid0", CheckID: "auth",
			Severity:    audit.SeverityCritical,
			Title:       fmt.Sprintf("Multiple accounts with UID 0: %s", strings.Join(roots, ", ")),
			Remediation: "Only root should have UID 0. Remove or change UID of other accounts",
			References:  []string{"CIS 6.2.2"},
		}}
	}
	return []audit.Finding{{
		ID: "auth-multiple-uid0", CheckID: "auth",
		Severity: audit.SeverityPass,
		Title:    "Only root has UID 0",
	}}
}

func checkPasswordlessAccounts(ctx context.Context, col collector.Collector) []audit.Finding {
	out, err := col.Exec(ctx, "awk -F: '($2 == \"\" || $2 == \"!\") && $1 != \"root\" {print $1}' /etc/shadow 2>/dev/null")
	if err != nil {
		return nil
	}
	accounts := strings.TrimSpace(string(out))
	if accounts == "" {
		return []audit.Finding{{
			ID: "auth-passwordless", CheckID: "auth",
			Severity: audit.SeverityPass,
			Title:    "No passwordless accounts",
		}}
	}
	return []audit.Finding{{
		ID: "auth-passwordless", CheckID: "auth",
		Severity:    audit.SeverityFail,
		Title:       "Accounts without password: " + accounts,
		Remediation: "Lock these accounts: passwd -l <user>",
		References:  []string{"CIS 6.2.1"},
	}}
}

func checkSystemShells(facts *audit.Facts) []audit.Finding {
	if facts == nil {
		return nil
	}
	loginShells := map[string]bool{"/bin/bash": true, "/bin/sh": true, "/bin/zsh": true, "/usr/bin/bash": true, "/usr/bin/zsh": true}
	systemAccounts := []string{}

	for _, u := range facts.Users {
		if u.UID == "0" || u.Name == "root" {
			continue
		}
		// System accounts typically have UID < 1000
		uid, _ := strconv.Atoi(u.UID)
		if uid >= 1000 {
			continue
		}
		if loginShells[u.Shell] {
			systemAccounts = append(systemAccounts, u.Name)
		}
	}

	if len(systemAccounts) > 0 {
		return []audit.Finding{{
			ID: "auth-system-shells", CheckID: "auth",
			Severity:    audit.SeverityWarn,
			Title:       fmt.Sprintf("System accounts with login shell: %s", strings.Join(systemAccounts, ", ")),
			Remediation: "Set shell to /usr/sbin/nologin for system accounts",
			References:  []string{"CIS 5.5.2"},
		}}
	}
	return []audit.Finding{{
		ID: "auth-system-shells", CheckID: "auth",
		Severity: audit.SeverityPass,
		Title:    "No system accounts with login shell",
	}}
}

func checkPasswordHashing(ctx context.Context, col collector.Collector) []audit.Finding {
	out, err := col.Exec(ctx, "grep -E '^ENCRYPT_METHOD' /etc/login.defs 2>/dev/null")
	if err != nil {
		return nil
	}
	line := strings.TrimSpace(string(out))
	if strings.Contains(strings.ToUpper(line), "SHA512") || strings.Contains(strings.ToUpper(line), "YESCRYPT") {
		return []audit.Finding{{
			ID: "auth-password-hashing", CheckID: "auth",
			Severity: audit.SeverityPass,
			Title:    "Strong password hashing: " + line,
		}}
	}
	return []audit.Finding{{
		ID: "auth-password-hashing", CheckID: "auth",
		Severity:    audit.SeverityFail,
		Title:       "Weak password hashing method: " + line,
		Remediation: "Set ENCRYPT_METHOD SHA512 or YESCRYPT in /etc/login.defs",
		References:  []string{"CIS 5.4.4"},
	}}
}

func checkPasswordAging(ctx context.Context, col collector.Collector) []audit.Finding {
	out, err := col.Exec(ctx, "grep -E '^PASS_MAX_DAYS|^PASS_MIN_DAYS|^PASS_WARN_AGE' /etc/login.defs 2>/dev/null")
	if err != nil {
		return nil
	}

	values := make(map[string]string)
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			values[parts[0]] = parts[1]
		}
	}

	var findings []audit.Finding
	if max, ok := values["PASS_MAX_DAYS"]; ok && max != "99999" {
		findings = append(findings, audit.Finding{
			ID: "auth-pass-max-days", CheckID: "auth",
			Severity: audit.SeverityPass,
			Title:    fmt.Sprintf("Password max age: %s days", max),
		})
	} else {
		findings = append(findings, audit.Finding{
			ID: "auth-pass-max-days", CheckID: "auth",
			Severity:    audit.SeverityInfo,
			Title:       "Password expiration not enforced",
			Remediation: "Set PASS_MAX_DAYS 365 in /etc/login.defs",
			References:  []string{"CIS 5.5.1.1"},
		})
	}

	return findings
}

func checkSudoers(ctx context.Context, col collector.Collector) []audit.Finding {
	out, err := col.Exec(ctx, "grep -rE 'NOPASSWD' /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -v '^#'")
	if err != nil || strings.TrimSpace(string(out)) == "" {
		return []audit.Finding{{
			ID: "auth-sudo-nopasswd", CheckID: "auth",
			Severity: audit.SeverityPass,
			Title:    "No NOPASSWD rules in sudoers",
		}}
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	return []audit.Finding{{
		ID: "auth-sudo-nopasswd", CheckID: "auth",
		Severity:    audit.SeverityWarn,
		Title:       fmt.Sprintf("NOPASSWD sudo rules found (%d)", len(lines)),
		Evidence:    strings.TrimSpace(string(out)),
		Remediation: "Review NOPASSWD rules. Remove unless strictly required",
		References:  []string{"CIS 5.3.4"},
	}}
}

func checkFailedLogins(ctx context.Context, col collector.Collector) []audit.Finding {
	out, err := col.Exec(ctx, "grep -c 'Failed password' /var/log/auth.log 2>/dev/null || journalctl -u sshd --since '24 hours ago' 2>/dev/null | grep -c 'Failed password'")
	if err != nil {
		return nil
	}
	count := strings.TrimSpace(string(out))
	if count == "" || count == "0" {
		return []audit.Finding{{
			ID: "auth-failed-logins", CheckID: "auth",
			Severity: audit.SeverityPass,
			Title:    "No failed login attempts in last 24h",
		}}
	}
	return []audit.Finding{{
		ID: "auth-failed-logins", CheckID: "auth",
		Severity: audit.SeverityInfo,
		Title:    fmt.Sprintf("%s failed login attempts in last 24h", count),
	}}
}
