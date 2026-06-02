package logging

import (
	"context"
	"strings"

	"github.com/Siovos/siovos-audit/pkg/audit"
	"github.com/Siovos/siovos-audit/pkg/collector"
)

type Check struct{}

func New() *Check { return &Check{} }

func (c *Check) ID() string       { return "logging" }
func (c *Check) Name() string     { return "Logging" }
func (c *Check) Category() string { return "logging" }

func (c *Check) Run(ctx context.Context, col collector.Collector) ([]audit.Finding, error) {
	var findings []audit.Finding

	findings = append(findings, checkSyslogDaemon(ctx, col)...)
	findings = append(findings, checkAuditd(ctx, col)...)
	findings = append(findings, checkLogrotate(ctx, col)...)
	findings = append(findings, checkAuthLog(ctx, col)...)
	findings = append(findings, checkRemoteLogging(ctx, col)...)

	return findings, nil
}

func checkSyslogDaemon(ctx context.Context, col collector.Collector) []audit.Finding {
	out, err := col.Exec(ctx, "systemctl is-active rsyslog 2>/dev/null || systemctl is-active systemd-journald 2>/dev/null || systemctl is-active syslog-ng 2>/dev/null")
	if err != nil {
		return []audit.Finding{{
			ID: "logging-syslog", CheckID: "logging",
			Severity:    audit.SeverityFail,
			Title:       "No syslog daemon detected",
			Remediation: "Install and enable rsyslog or ensure systemd-journald is running",
			References:  []string{"CIS 4.2.1"},
		}}
	}
	if strings.Contains(string(out), "active") {
		return []audit.Finding{{
			ID: "logging-syslog", CheckID: "logging",
			Severity: audit.SeverityPass,
			Title:    "Syslog daemon active",
		}}
	}
	return nil
}

func checkAuditd(ctx context.Context, col collector.Collector) []audit.Finding {
	out, err := col.Exec(ctx, "systemctl is-active auditd 2>/dev/null")
	if err != nil || !strings.Contains(string(out), "active") {
		return []audit.Finding{{
			ID: "logging-auditd", CheckID: "logging",
			Severity:    audit.SeverityWarn,
			Title:       "Audit daemon (auditd) not active",
			Remediation: "Install and enable auditd: apt install auditd && systemctl enable --now auditd",
			References:  []string{"CIS 4.1.1"},
		}}
	}

	// Check if audit rules exist
	rules, err := col.Exec(ctx, "auditctl -l 2>/dev/null | wc -l")
	if err == nil {
		count := strings.TrimSpace(string(rules))
		if count == "0" {
			return []audit.Finding{
				{ID: "logging-auditd", CheckID: "logging", Severity: audit.SeverityPass, Title: "Audit daemon active"},
				{ID: "logging-audit-rules", CheckID: "logging", Severity: audit.SeverityWarn, Title: "Auditd active but no audit rules configured", Remediation: "Add audit rules in /etc/audit/rules.d/"},
			}
		}
		return []audit.Finding{
			{ID: "logging-auditd", CheckID: "logging", Severity: audit.SeverityPass, Title: "Audit daemon active"},
			{ID: "logging-audit-rules", CheckID: "logging", Severity: audit.SeverityPass, Title: "Audit rules configured (" + count + " rules)"},
		}
	}

	return []audit.Finding{{
		ID: "logging-auditd", CheckID: "logging",
		Severity: audit.SeverityPass,
		Title:    "Audit daemon active",
	}}
}

func checkLogrotate(ctx context.Context, col collector.Collector) []audit.Finding {
	out, err := col.Exec(ctx, "test -f /etc/logrotate.conf && echo found 2>/dev/null")
	if err != nil || !strings.Contains(string(out), "found") {
		return []audit.Finding{{
			ID: "logging-logrotate", CheckID: "logging",
			Severity:    audit.SeverityWarn,
			Title:       "Logrotate not configured",
			Remediation: "Install logrotate: apt install logrotate",
		}}
	}
	return []audit.Finding{{
		ID: "logging-logrotate", CheckID: "logging",
		Severity: audit.SeverityPass,
		Title:    "Logrotate configured",
	}}
}

func checkAuthLog(ctx context.Context, col collector.Collector) []audit.Finding {
	// Check auth.log or journal
	out, err := col.Exec(ctx, "test -f /var/log/auth.log && stat -c '%a' /var/log/auth.log 2>/dev/null")
	if err == nil {
		perms := strings.TrimSpace(string(out))
		if perms == "640" || perms == "600" {
			return []audit.Finding{{
				ID: "logging-auth-log", CheckID: "logging",
				Severity: audit.SeverityPass,
				Title:    "Auth log exists with correct permissions (" + perms + ")",
			}}
		}
		return []audit.Finding{{
			ID: "logging-auth-log", CheckID: "logging",
			Severity:    audit.SeverityWarn,
			Title:       "Auth log permissions too open (" + perms + ")",
			Remediation: "chmod 640 /var/log/auth.log",
		}}
	}

	// Maybe using journald only
	out, err = col.Exec(ctx, "journalctl -u sshd --since '1 hour ago' -n 1 2>/dev/null")
	if err == nil && len(out) > 0 {
		return []audit.Finding{{
			ID: "logging-auth-log", CheckID: "logging",
			Severity: audit.SeverityPass,
			Title:    "Auth logging via journald",
		}}
	}

	return []audit.Finding{{
		ID: "logging-auth-log", CheckID: "logging",
		Severity:    audit.SeverityFail,
		Title:       "No auth logging detected",
		Remediation: "Ensure rsyslog is configured to log auth events or journald is active",
	}}
}

func checkRemoteLogging(ctx context.Context, col collector.Collector) []audit.Finding {
	out, err := col.Exec(ctx, "grep -rE '^[^#]*@@' /etc/rsyslog.conf /etc/rsyslog.d/ 2>/dev/null")
	if err == nil && strings.TrimSpace(string(out)) != "" {
		return []audit.Finding{{
			ID: "logging-remote", CheckID: "logging",
			Severity: audit.SeverityPass,
			Title:    "Remote logging configured",
		}}
	}
	return []audit.Finding{{
		ID: "logging-remote", CheckID: "logging",
		Severity: audit.SeverityInfo,
		Title:    "No remote logging configured",
	}}
}
