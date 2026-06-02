package explain_test

import (
	"testing"

	"github.com/Siovos/siovos-audit/pkg/audit"
	"github.com/Siovos/siovos-audit/pkg/explain"
)

func TestEnrich_AddsDescription(t *testing.T) {
	findings := []audit.Finding{
		{ID: "ssh-password-auth", Severity: audit.SeverityFail, Title: "Password auth enabled"},
		{ID: "ssh-root-login", Severity: audit.SeverityFail, Title: "Root login allowed"},
	}

	enriched := explain.Enrich(findings)

	for _, f := range enriched {
		if f.Description == "" {
			t.Errorf("expected description for %s", f.ID)
		}
		if f.Remediation == "" {
			t.Errorf("expected remediation for %s", f.ID)
		}
	}
}

func TestEnrich_SkipsPass(t *testing.T) {
	findings := []audit.Finding{
		{ID: "ssh-password-auth", Severity: audit.SeverityPass, Title: "Password auth disabled"},
	}

	enriched := explain.Enrich(findings)

	if enriched[0].Description != "" {
		t.Error("PASS findings should not get descriptions")
	}
}

func TestEnrich_PrefixMatch(t *testing.T) {
	findings := []audit.Finding{
		{ID: "firewall-open-port-8080", Severity: audit.SeverityWarn, Title: "Port 8080 open"},
	}

	enriched := explain.Enrich(findings)

	if enriched[0].Description == "" {
		t.Error("prefix match should add description for firewall-open-port-*")
	}
}

func TestEnrich_PreservesExisting(t *testing.T) {
	findings := []audit.Finding{
		{ID: "ssh-password-auth", Severity: audit.SeverityFail, Description: "Custom desc", Remediation: "Short fix"},
	}

	enriched := explain.Enrich(findings)

	if enriched[0].Description != "Custom desc" {
		t.Error("should preserve existing description")
	}
}
