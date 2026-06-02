package cron

import (
	"context"
	"fmt"
	"strings"

	"github.com/Siovos/siovos-audit/pkg/audit"
	"github.com/Siovos/siovos-audit/pkg/collector"
)

type Check struct{}

func New() *Check { return &Check{} }

func (c *Check) ID() string       { return "cron" }
func (c *Check) Name() string     { return "Scheduled Tasks" }
func (c *Check) Category() string { return "cron" }

func (c *Check) Run(ctx context.Context, col collector.Collector) ([]audit.Finding, error) {
	var findings []audit.Finding

	findings = append(findings, checkCronDaemon(ctx, col)...)
	findings = append(findings, checkCronPermissions(ctx, col)...)
	findings = append(findings, checkCronJobs(ctx, col)...)
	findings = append(findings, checkAtJobs(ctx, col)...)
	findings = append(findings, checkSystemdTimers(ctx, col)...)

	return findings, nil
}

func checkCronDaemon(ctx context.Context, col collector.Collector) []audit.Finding {
	out, err := col.Exec(ctx, "systemctl is-active cron 2>/dev/null || systemctl is-active crond 2>/dev/null")
	if err != nil || !strings.Contains(string(out), "active") {
		return []audit.Finding{{
			ID: "cron-daemon", CheckID: "cron",
			Severity: audit.SeverityInfo,
			Title:    "Cron daemon not active",
		}}
	}
	return []audit.Finding{{
		ID: "cron-daemon", CheckID: "cron",
		Severity: audit.SeverityPass,
		Title:    "Cron daemon active",
	}}
}

func checkCronPermissions(ctx context.Context, col collector.Collector) []audit.Finding {
	paths := []struct {
		path string
		name string
		perm string
	}{
		{"/etc/crontab", "crontab", "600"},
		{"/etc/cron.d", "cron.d", "700"},
		{"/etc/cron.daily", "cron.daily", "700"},
		{"/etc/cron.hourly", "cron.hourly", "700"},
		{"/etc/cron.weekly", "cron.weekly", "700"},
		{"/etc/cron.monthly", "cron.monthly", "700"},
	}

	var findings []audit.Finding
	for _, p := range paths {
		out, err := col.Exec(ctx, fmt.Sprintf("stat -c '%%a' %s 2>/dev/null", p.path))
		if err != nil {
			continue
		}
		perms := strings.TrimSpace(string(out))
		if perms <= p.perm {
			findings = append(findings, audit.Finding{
				ID: fmt.Sprintf("cron-perms-%s", p.name), CheckID: "cron",
				Severity: audit.SeverityPass,
				Title:    fmt.Sprintf("%s permissions OK (%s)", p.name, perms),
			})
		} else {
			findings = append(findings, audit.Finding{
				ID: fmt.Sprintf("cron-perms-%s", p.name), CheckID: "cron",
				Severity:    audit.SeverityWarn,
				Title:       fmt.Sprintf("%s permissions too open (%s)", p.name, perms),
				Remediation: fmt.Sprintf("chmod %s %s", p.perm, p.path),
				References:  []string{"CIS 5.1"},
			})
		}
	}
	return findings
}

func checkCronJobs(ctx context.Context, col collector.Collector) []audit.Finding {
	out, err := col.Exec(ctx, "crontab -l 2>/dev/null")
	if err != nil || strings.TrimSpace(string(out)) == "" || strings.Contains(string(out), "no crontab") {
		return []audit.Finding{{
			ID: "cron-root-jobs", CheckID: "cron",
			Severity: audit.SeverityPass,
			Title:    "No root crontab entries",
		}}
	}

	lines := 0
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			lines++
		}
	}

	return []audit.Finding{{
		ID: "cron-root-jobs", CheckID: "cron",
		Severity: audit.SeverityInfo,
		Title:    fmt.Sprintf("Root crontab: %d entries", lines),
		Evidence: strings.TrimSpace(string(out)),
	}}
}

func checkAtJobs(ctx context.Context, col collector.Collector) []audit.Finding {
	out, err := col.Exec(ctx, "atq 2>/dev/null | wc -l")
	if err != nil {
		return nil
	}
	count := strings.TrimSpace(string(out))
	if count == "0" || count == "" {
		return []audit.Finding{{
			ID: "cron-at-jobs", CheckID: "cron",
			Severity: audit.SeverityPass,
			Title:    "No pending at jobs",
		}}
	}
	return []audit.Finding{{
		ID: "cron-at-jobs", CheckID: "cron",
		Severity: audit.SeverityInfo,
		Title:    fmt.Sprintf("%s pending at jobs", count),
	}}
}

func checkSystemdTimers(ctx context.Context, col collector.Collector) []audit.Finding {
	out, err := col.Exec(ctx, "systemctl list-timers --no-pager --no-legend 2>/dev/null | wc -l")
	if err != nil {
		return nil
	}
	count := strings.TrimSpace(string(out))
	return []audit.Finding{{
		ID: "cron-systemd-timers", CheckID: "cron",
		Severity: audit.SeverityInfo,
		Title:    fmt.Sprintf("%s active systemd timers", count),
	}}
}
