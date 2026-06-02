package packages

import (
	"context"
	"fmt"
	"strings"

	"github.com/Siovos/siovos-audit/pkg/audit"
	"github.com/Siovos/siovos-audit/pkg/collector"
)

type Check struct{}

func New() *Check { return &Check{} }

func (c *Check) ID() string       { return "packages" }
func (c *Check) Name() string     { return "Packages" }
func (c *Check) Category() string { return "packages" }

func (c *Check) Run(ctx context.Context, col collector.Collector) ([]audit.Finding, error) {
	var findings []audit.Finding

	findings = append(findings, checkGPGSigning(ctx, col)...)
	findings = append(findings, checkSecurityRepo(ctx, col)...)
	findings = append(findings, checkMultipleKernels(ctx, col)...)
	findings = append(findings, checkPackageAudit(ctx, col)...)

	return findings, nil
}

func checkGPGSigning(ctx context.Context, col collector.Collector) []audit.Finding {
	// Check APT repos have signed packages
	out, err := col.Exec(ctx, "grep -rE '^deb ' /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null | grep -c 'trusted=yes'")
	if err != nil {
		// Try RPM
		out, err = col.Exec(ctx, "grep -rE '^gpgcheck' /etc/yum.repos.d/ 2>/dev/null | grep -c 'gpgcheck=0'")
		if err != nil {
			return nil
		}
	}
	count := strings.TrimSpace(string(out))
	if count == "0" || count == "" {
		return []audit.Finding{{
			ID: "pkg-gpg", CheckID: "packages",
			Severity: audit.SeverityPass,
			Title:    "All package repositories use GPG verification",
		}}
	}
	return []audit.Finding{{
		ID: "pkg-gpg", CheckID: "packages",
		Severity:    audit.SeverityWarn,
		Title:       fmt.Sprintf("%s repositories without GPG verification", count),
		Remediation: "Remove 'trusted=yes' from APT sources or set gpgcheck=1 in YUM repos",
	}}
}

func checkSecurityRepo(ctx context.Context, col collector.Collector) []audit.Finding {
	out, err := col.Exec(ctx, "grep -rE 'security' /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null")
	if err == nil && strings.TrimSpace(string(out)) != "" {
		return []audit.Finding{{
			ID: "pkg-security-repo", CheckID: "packages",
			Severity: audit.SeverityPass,
			Title:    "Security repository configured",
		}}
	}
	// RPM-based
	out, err = col.Exec(ctx, "yum repolist 2>/dev/null | grep -i security")
	if err == nil && strings.TrimSpace(string(out)) != "" {
		return []audit.Finding{{
			ID: "pkg-security-repo", CheckID: "packages",
			Severity: audit.SeverityPass,
			Title:    "Security repository configured",
		}}
	}
	return []audit.Finding{{
		ID: "pkg-security-repo", CheckID: "packages",
		Severity:    audit.SeverityWarn,
		Title:       "No security repository detected",
		Remediation: "Ensure security updates repository is configured",
	}}
}

func checkMultipleKernels(ctx context.Context, col collector.Collector) []audit.Finding {
	out, err := col.Exec(ctx, "dpkg -l 'linux-image-*' 2>/dev/null | grep '^ii' | wc -l")
	if err != nil {
		out, err = col.Exec(ctx, "rpm -q kernel 2>/dev/null | wc -l")
		if err != nil {
			return nil
		}
	}
	count := strings.TrimSpace(string(out))
	if count == "0" || count == "1" {
		return []audit.Finding{{
			ID: "pkg-kernels", CheckID: "packages",
			Severity: audit.SeverityPass,
			Title:    "Single kernel installed",
		}}
	}
	return []audit.Finding{{
		ID: "pkg-kernels", CheckID: "packages",
		Severity: audit.SeverityInfo,
		Title:    fmt.Sprintf("%s kernel packages installed", count),
	}}
}

func checkPackageAudit(ctx context.Context, col collector.Collector) []audit.Finding {
	tools := []struct{ cmd, name string }{
		{"which debsecan", "debsecan"},
		{"which debsums", "debsums"},
		{"which arch-audit", "arch-audit"},
	}
	for _, t := range tools {
		out, err := col.Exec(ctx, t.cmd+" 2>/dev/null")
		if err == nil && strings.TrimSpace(string(out)) != "" {
			return []audit.Finding{{
				ID: "pkg-audit-tool", CheckID: "packages",
				Severity: audit.SeverityPass,
				Title:    "Package audit tool available: " + t.name,
			}}
		}
	}
	return []audit.Finding{{
		ID: "pkg-audit-tool", CheckID: "packages",
		Severity: audit.SeverityInfo,
		Title:    "No package audit tool installed (debsecan, debsums)",
	}}
}
