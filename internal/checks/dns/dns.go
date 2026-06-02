package dns

import (
	"context"
	"strings"

	"github.com/Siovos/siovos-audit/pkg/audit"
	"github.com/Siovos/siovos-audit/pkg/collector"
)

type Check struct{}

func New() *Check { return &Check{} }

func (c *Check) ID() string       { return "dns" }
func (c *Check) Name() string     { return "DNS & Domain" }
func (c *Check) Category() string { return "dns" }

func (c *Check) Run(ctx context.Context, col collector.Collector) ([]audit.Finding, error) {
	// Try to determine the server's hostname/domain
	out, err := col.Exec(ctx, "hostname -f 2>/dev/null")
	if err != nil {
		return []audit.Finding{{
			ID: "dns-no-hostname", CheckID: "dns",
			Severity: audit.SeverityInfo,
			Title:    "Could not determine server hostname",
		}}, nil
	}

	hostname := strings.TrimSpace(string(out))
	if hostname == "" || !strings.Contains(hostname, ".") {
		return []audit.Finding{{
			ID: "dns-no-domain", CheckID: "dns",
			Severity: audit.SeverityInfo,
			Title:    "No domain configured (hostname: " + hostname + ")",
		}}, nil
	}

	var findings []audit.Finding
	domain := hostname

	findings = append(findings, checkSPF(ctx, col, domain)...)
	findings = append(findings, checkDMARC(ctx, col, domain)...)

	return findings, nil
}

func checkSPF(ctx context.Context, col collector.Collector, domain string) []audit.Finding {
	out, err := col.Exec(ctx, "dig +short TXT "+domain+" 2>/dev/null | grep -i spf")
	if err != nil || strings.TrimSpace(string(out)) == "" {
		return []audit.Finding{{
			ID: "dns-spf", CheckID: "dns",
			Severity:    audit.SeverityWarn,
			Title:       "No SPF record for " + domain,
			Remediation: "Add a TXT record: v=spf1 ... -all",
		}}
	}
	return []audit.Finding{{
		ID: "dns-spf", CheckID: "dns",
		Severity: audit.SeverityPass,
		Title:    "SPF record configured",
		Evidence: strings.TrimSpace(string(out)),
	}}
}

func checkDMARC(ctx context.Context, col collector.Collector, domain string) []audit.Finding {
	out, err := col.Exec(ctx, "dig +short TXT _dmarc."+domain+" 2>/dev/null")
	if err != nil || strings.TrimSpace(string(out)) == "" {
		return []audit.Finding{{
			ID: "dns-dmarc", CheckID: "dns",
			Severity:    audit.SeverityWarn,
			Title:       "No DMARC record for " + domain,
			Remediation: "Add a TXT record at _dmarc." + domain + ": v=DMARC1; p=reject;",
		}}
	}
	return []audit.Finding{{
		ID: "dns-dmarc", CheckID: "dns",
		Severity: audit.SeverityPass,
		Title:    "DMARC record configured",
		Evidence: strings.TrimSpace(string(out)),
	}}
}
