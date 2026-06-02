package time

import (
	"context"
	"strings"

	"github.com/Siovos/siovos-audit/pkg/audit"
	"github.com/Siovos/siovos-audit/pkg/collector"
)

type Check struct{}

func New() *Check { return &Check{} }

func (c *Check) ID() string       { return "time" }
func (c *Check) Name() string     { return "Time Sync" }
func (c *Check) Category() string { return "time" }

func (c *Check) Run(ctx context.Context, col collector.Collector) ([]audit.Finding, error) {
	var findings []audit.Finding

	findings = append(findings, checkNTPDaemon(ctx, col)...)
	findings = append(findings, checkTimeSynced(ctx, col)...)

	return findings, nil
}

func checkNTPDaemon(ctx context.Context, col collector.Collector) []audit.Finding {
	daemons := []string{"chronyd", "ntpd", "systemd-timesyncd"}
	for _, d := range daemons {
		out, err := col.Exec(ctx, "systemctl is-active "+d+" 2>/dev/null")
		if err == nil && strings.Contains(string(out), "active") {
			return []audit.Finding{{
				ID: "time-ntp-daemon", CheckID: "time",
				Severity: audit.SeverityPass,
				Title:    "NTP daemon active: " + d,
			}}
		}
	}
	return []audit.Finding{{
		ID: "time-ntp-daemon", CheckID: "time",
		Severity:    audit.SeverityWarn,
		Title:       "No NTP daemon active",
		Remediation: "Install chrony or enable systemd-timesyncd: timedatectl set-ntp true",
		References:  []string{"CIS 2.2.1"},
	}}
}

func checkTimeSynced(ctx context.Context, col collector.Collector) []audit.Finding {
	out, err := col.Exec(ctx, "timedatectl show --property=NTPSynchronized --value 2>/dev/null")
	if err != nil {
		return nil
	}
	val := strings.TrimSpace(string(out))
	if val == "yes" {
		return []audit.Finding{{
			ID: "time-synced", CheckID: "time",
			Severity: audit.SeverityPass,
			Title:    "System clock synchronized",
		}}
	}
	return []audit.Finding{{
		ID: "time-synced", CheckID: "time",
		Severity:    audit.SeverityWarn,
		Title:       "System clock not synchronized",
		Remediation: "Check NTP configuration: timedatectl status",
	}}
}
