package backup

import (
	"context"
	"strings"

	"github.com/Siovos/siovos-audit/pkg/audit"
	"github.com/Siovos/siovos-audit/pkg/collector"
)

type Check struct{}

func New() *Check { return &Check{} }

func (c *Check) ID() string       { return "backup" }
func (c *Check) Name() string     { return "Backups" }
func (c *Check) Category() string { return "backup" }

func (c *Check) Run(ctx context.Context, col collector.Collector) ([]audit.Finding, error) {
	var findings []audit.Finding
	found := false

	tools := []struct {
		cmd  string
		name string
	}{
		{"which restic 2>/dev/null", "restic"},
		{"which borg 2>/dev/null", "borg"},
		{"which duplicity 2>/dev/null", "duplicity"},
		{"which rdiff-backup 2>/dev/null", "rdiff-backup"},
	}

	for _, t := range tools {
		out, err := col.Exec(ctx, t.cmd)
		if err == nil && strings.TrimSpace(string(out)) != "" {
			findings = append(findings, audit.Finding{
				ID: "backup-tool-" + t.name, CheckID: "backup",
				Severity: audit.SeverityPass,
				Title:    "Backup tool installed: " + t.name,
			})
			found = true
		}
	}

	// Check for backup-related cron jobs
	out, err := col.Exec(ctx, "grep -rlE 'backup|restic|borg|duplicity|pg_dump|mysqldump' /etc/cron* /var/spool/cron 2>/dev/null | head -5")
	if err == nil && strings.TrimSpace(string(out)) != "" {
		findings = append(findings, audit.Finding{
			ID: "backup-cron", CheckID: "backup",
			Severity: audit.SeverityPass,
			Title:    "Backup-related cron jobs detected",
		})
		found = true
	}

	// Check for systemd backup timers
	out, err = col.Exec(ctx, "systemctl list-timers --no-pager --no-legend 2>/dev/null | grep -iE 'backup|restic|borg'")
	if err == nil && strings.TrimSpace(string(out)) != "" {
		findings = append(findings, audit.Finding{
			ID: "backup-timer", CheckID: "backup",
			Severity: audit.SeverityPass,
			Title:    "Backup systemd timer detected",
		})
		found = true
	}

	if !found {
		findings = append(findings, audit.Finding{
			ID: "backup-none", CheckID: "backup",
			Severity:    audit.SeverityWarn,
			Title:       "No backup tools or schedules detected",
			Remediation: "Install a backup tool (restic, borg) and configure automated backups",
		})
	}

	return findings, nil
}
