package integrity

import (
	"context"
	"strings"

	"github.com/Siovos/siovos-audit/pkg/audit"
	"github.com/Siovos/siovos-audit/pkg/collector"
)

type Check struct{}

func New() *Check { return &Check{} }

func (c *Check) ID() string       { return "integrity" }
func (c *Check) Name() string     { return "File Integrity" }
func (c *Check) Category() string { return "integrity" }

func (c *Check) Run(ctx context.Context, col collector.Collector) ([]audit.Finding, error) {
	var findings []audit.Finding
	found := false

	tools := []struct {
		cmd  string
		name string
	}{
		{"which aide 2>/dev/null", "AIDE"},
		{"which tripwire 2>/dev/null", "Tripwire"},
		{"which ossec-control 2>/dev/null", "OSSEC"},
		{"which wazuh-control 2>/dev/null", "Wazuh"},
		{"which osqueryi 2>/dev/null", "osquery"},
		{"systemctl is-active wazuh-agent 2>/dev/null | grep active", "Wazuh agent"},
	}

	for _, t := range tools {
		out, err := col.Exec(ctx, t.cmd)
		if err == nil && strings.TrimSpace(string(out)) != "" {
			findings = append(findings, audit.Finding{
				ID: "integrity-" + strings.ToLower(strings.Split(t.name, " ")[0]), CheckID: "integrity",
				Severity: audit.SeverityPass,
				Title:    t.name + " installed",
			})
			found = true
		}
	}

	if !found {
		findings = append(findings, audit.Finding{
			ID: "integrity-none", CheckID: "integrity",
			Severity:    audit.SeverityWarn,
			Title:       "No file integrity monitoring tool installed",
			Remediation: "Consider installing AIDE, Tripwire, or Wazuh",
		})
	}

	return findings, nil
}
