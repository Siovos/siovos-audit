package shells

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

func (c *Check) ID() string       { return "shells" }
func (c *Check) Name() string     { return "Shells & Home" }
func (c *Check) Category() string { return "shells" }

func (c *Check) Run(ctx context.Context, col collector.Collector) ([]audit.Finding, error) {
	var findings []audit.Finding

	findings = append(findings, checkTMOUT(ctx, col)...)
	findings = append(findings, checkUmaskProfile(ctx, col)...)
	findings = append(findings, checkHomePermissions(ctx, col)...)

	return findings, nil
}

func checkTMOUT(ctx context.Context, col collector.Collector) []audit.Finding {
	out, err := col.Exec(ctx, "grep -rE '^\\s*TMOUT=' /etc/profile /etc/profile.d/ /etc/bashrc /etc/bash.bashrc 2>/dev/null")
	if err != nil || strings.TrimSpace(string(out)) == "" {
		return []audit.Finding{{
			ID: "shells-tmout", CheckID: "shells",
			Severity:    audit.SeverityWarn,
			Title:       "No idle session timeout (TMOUT) configured",
			Remediation: "Add 'TMOUT=900; readonly TMOUT; export TMOUT' to /etc/profile.d/timeout.sh",
			References:  []string{"CIS 5.5.4"},
		}}
	}
	return []audit.Finding{{
		ID: "shells-tmout", CheckID: "shells",
		Severity: audit.SeverityPass,
		Title:    "Idle session timeout configured",
		Evidence: strings.TrimSpace(string(out)),
	}}
}

func checkUmaskProfile(ctx context.Context, col collector.Collector) []audit.Finding {
	out, err := col.Exec(ctx, "grep -rE '^\\s*umask\\s+0[0-7]{2}' /etc/profile /etc/profile.d/ /etc/bashrc /etc/bash.bashrc 2>/dev/null")
	if err != nil || strings.TrimSpace(string(out)) == "" {
		return []audit.Finding{{
			ID: "shells-umask", CheckID: "shells",
			Severity: audit.SeverityInfo,
			Title:    "No explicit umask in shell profiles",
		}}
	}
	// Check if umask is restrictive enough
	output := strings.TrimSpace(string(out))
	if strings.Contains(output, "027") || strings.Contains(output, "077") {
		return []audit.Finding{{
			ID: "shells-umask", CheckID: "shells",
			Severity: audit.SeverityPass,
			Title:    "Restrictive umask in shell profiles",
			Evidence: output,
		}}
	}
	return []audit.Finding{{
		ID: "shells-umask", CheckID: "shells",
		Severity:    audit.SeverityWarn,
		Title:       "Umask in shell profiles not restrictive enough",
		Evidence:    output,
		Remediation: "Set umask 027 in /etc/profile",
	}}
}

func checkHomePermissions(ctx context.Context, col collector.Collector) []audit.Finding {
	facts := audit.GetFacts(ctx)
	if facts == nil {
		return nil
	}

	var findings []audit.Finding
	for _, u := range facts.Users {
		if u.Home == "/" || u.Home == "/nonexistent" || u.Home == "/dev/null" || u.Home == "" {
			continue
		}
		// Only check real user homes (UID >= 1000 or root)
		uid, _ := strconv.Atoi(u.UID)
		if uid != 0 && uid < 1000 {
			continue
		}

		out, err := col.Exec(ctx, fmt.Sprintf("stat -c '%%a' %s 2>/dev/null", u.Home))
		if err != nil {
			continue
		}
		perms := strings.TrimSpace(string(out))
		if perms <= "750" {
			findings = append(findings, audit.Finding{
				ID: fmt.Sprintf("shells-home-%s", u.Name), CheckID: "shells",
				Severity: audit.SeverityPass,
				Title:    fmt.Sprintf("Home %s permissions OK (%s)", u.Name, perms),
			})
		} else {
			findings = append(findings, audit.Finding{
				ID: fmt.Sprintf("shells-home-%s", u.Name), CheckID: "shells",
				Severity:    audit.SeverityWarn,
				Title:       fmt.Sprintf("Home %s too open (%s)", u.Name, perms),
				Remediation: fmt.Sprintf("chmod 750 %s", u.Home),
				References:  []string{"CIS 6.2.6"},
			})
		}
	}
	return findings
}
