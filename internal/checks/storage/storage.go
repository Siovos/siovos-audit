package storage

import (
	"context"
	"strings"

	"github.com/Siovos/siovos-audit/pkg/audit"
	"github.com/Siovos/siovos-audit/pkg/collector"
)

type Check struct{}

func New() *Check { return &Check{} }

func (c *Check) ID() string       { return "storage" }
func (c *Check) Name() string     { return "Storage" }
func (c *Check) Category() string { return "storage" }

func (c *Check) Run(ctx context.Context, col collector.Collector) ([]audit.Finding, error) {
	var findings []audit.Finding

	findings = append(findings, checkNFSExports(ctx, col)...)
	findings = append(findings, checkUSBStorage(ctx, col)...)

	return findings, nil
}

func checkNFSExports(ctx context.Context, col collector.Collector) []audit.Finding {
	out, err := col.ReadFile(ctx, "/etc/exports")
	if err != nil {
		return nil
	}
	content := strings.TrimSpace(string(out))
	if content == "" {
		return nil
	}

	// Check for world-accessible exports
	if strings.Contains(content, "*(") {
		return []audit.Finding{{
			ID: "storage-nfs-world", CheckID: "storage",
			Severity:    audit.SeverityFail,
			Title:       "NFS export accessible to everyone",
			Evidence:    content,
			Remediation: "Restrict NFS exports to specific hosts/networks",
		}}
	}

	return []audit.Finding{{
		ID: "storage-nfs", CheckID: "storage",
		Severity: audit.SeverityInfo,
		Title:    "NFS exports configured",
	}}
}

func checkUSBStorage(ctx context.Context, col collector.Collector) []audit.Finding {
	out, err := col.Exec(ctx, "lsmod 2>/dev/null | grep usb_storage")
	if err != nil || strings.TrimSpace(string(out)) == "" {
		return []audit.Finding{{
			ID: "storage-usb", CheckID: "storage",
			Severity: audit.SeverityPass,
			Title:    "USB storage module not loaded",
		}}
	}
	return []audit.Finding{{
		ID: "storage-usb", CheckID: "storage",
		Severity: audit.SeverityInfo,
		Title:    "USB storage module loaded",
	}}
}
