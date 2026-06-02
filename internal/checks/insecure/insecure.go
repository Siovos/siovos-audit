package insecure

import (
	"context"
	"strings"

	"github.com/Siovos/siovos-audit/pkg/audit"
	"github.com/Siovos/siovos-audit/pkg/collector"
)

type Check struct{}

func New() *Check { return &Check{} }

func (c *Check) ID() string       { return "insecure" }
func (c *Check) Name() string     { return "Insecure Services" }
func (c *Check) Category() string { return "insecure" }

func (c *Check) Run(ctx context.Context, col collector.Collector) ([]audit.Finding, error) {
	services := []struct {
		pkg      string
		name     string
		severity audit.Severity
		ref      string
	}{
		{"telnetd", "Telnet server", audit.SeverityCritical, "CIS 2.1.1"},
		{"rsh-server", "RSH server", audit.SeverityCritical, "CIS 2.1.2"},
		{"nis", "NIS server", audit.SeverityFail, "CIS 2.1.5"},
		{"tftpd", "TFTP server", audit.SeverityFail, "CIS 2.1.6"},
		{"vsftpd", "FTP server (vsftpd)", audit.SeverityWarn, ""},
		{"proftpd", "FTP server (proftpd)", audit.SeverityWarn, ""},
		{"xinetd", "xinetd", audit.SeverityWarn, "CIS 2.1.7"},
		{"inetutils-inetd", "inetd", audit.SeverityWarn, ""},
		{"rsh-client", "RSH client", audit.SeverityWarn, "CIS 2.3.2"},
		{"telnet", "Telnet client", audit.SeverityInfo, "CIS 2.3.4"},
	}

	var findings []audit.Finding

	for _, svc := range services {
		out, err := col.Exec(ctx, "dpkg -l "+svc.pkg+" 2>/dev/null | grep '^ii' || rpm -q "+svc.pkg+" 2>/dev/null | grep -v 'not installed'")
		if err != nil || strings.TrimSpace(string(out)) == "" {
			continue
		}

		f := audit.Finding{
			ID:          "insecure-" + svc.pkg,
			CheckID:     "insecure",
			Severity:    svc.severity,
			Title:       svc.name + " installed",
			Remediation: "Remove: apt remove " + svc.pkg,
		}
		if svc.ref != "" {
			f.References = []string{svc.ref}
		}
		findings = append(findings, f)
	}

	if len(findings) == 0 {
		findings = append(findings, audit.Finding{
			ID: "insecure-none", CheckID: "insecure",
			Severity: audit.SeverityPass,
			Title:    "No insecure services detected",
		})
	}

	return findings, nil
}
