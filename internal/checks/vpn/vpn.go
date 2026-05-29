package vpn

import (
	"context"
	"fmt"
	"strings"

	"github.com/Siovos/siovos-audit/pkg/audit"
	"github.com/Siovos/siovos-audit/pkg/collector"
)

type Check struct{}

func New() *Check { return &Check{} }

func (c *Check) ID() string       { return "vpn" }
func (c *Check) Name() string     { return "VPN" }
func (c *Check) Category() string { return "vpn" }

func (c *Check) Run(ctx context.Context, col collector.Collector) ([]audit.Finding, error) {
	// Detect WireGuard
	out, err := col.Exec(ctx, "wg show 2>/dev/null")
	if err != nil || strings.TrimSpace(string(out)) == "" {
		return []audit.Finding{{
			ID:       "vpn-not-found",
			CheckID:  "vpn",
			Severity: audit.SeverityInfo,
			Title:    "WireGuard not detected on this server",
		}}, nil
	}

	var findings []audit.Finding
	findings = append(findings, checkWireGuardInterfaces(ctx, col)...)
	findings = append(findings, checkWireGuardKeys(ctx, col)...)
	findings = append(findings, checkWireGuardHandshake(ctx, col)...)

	return findings, nil
}

func checkWireGuardInterfaces(ctx context.Context, col collector.Collector) []audit.Finding {
	out, err := col.Exec(ctx, "wg show interfaces 2>/dev/null")
	if err != nil {
		return nil
	}

	ifaces := strings.Fields(strings.TrimSpace(string(out)))
	if len(ifaces) == 0 {
		return []audit.Finding{{
			ID:       "vpn-interfaces",
			CheckID:  "vpn",
			Severity: audit.SeverityWarn,
			Title:    "No WireGuard interfaces active",
		}}
	}

	return []audit.Finding{{
		ID:       "vpn-interfaces",
		CheckID:  "vpn",
		Severity: audit.SeverityPass,
		Title:    fmt.Sprintf("WireGuard active: %s", strings.Join(ifaces, ", ")),
	}}
}

func checkWireGuardKeys(ctx context.Context, col collector.Collector) []audit.Finding {
	// Check that private keys are not world-readable
	configPaths := []string{
		"/etc/wireguard/*.conf",
	}

	for _, pattern := range configPaths {
		out, err := col.Exec(ctx, fmt.Sprintf("stat -c '%%a %%n' %s 2>/dev/null", pattern))
		if err != nil {
			continue
		}

		var findings []audit.Finding
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			if line == "" {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			perms := fields[0]
			file := fields[1]

			if perms == "600" || perms == "640" || perms == "400" {
				findings = append(findings, audit.Finding{
					ID:       "vpn-key-perms-" + sanitize(file),
					CheckID:  "vpn",
					Severity: audit.SeverityPass,
					Title:    fmt.Sprintf("Config permissions OK: %s (%s)", file, perms),
				})
			} else {
				findings = append(findings, audit.Finding{
					ID:          "vpn-key-perms-" + sanitize(file),
					CheckID:     "vpn",
					Severity:    audit.SeverityFail,
					Title:       fmt.Sprintf("Config too permissive: %s (%s)", file, perms),
					Remediation: fmt.Sprintf("chmod 600 %s", file),
				})
			}
		}
		if len(findings) > 0 {
			return findings
		}
	}

	return nil
}

func checkWireGuardHandshake(ctx context.Context, col collector.Collector) []audit.Finding {
	out, err := col.Exec(ctx, "wg show all latest-handshakes 2>/dev/null")
	if err != nil {
		return nil
	}

	var findings []audit.Finding
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		// fields: interface, peer-pubkey, timestamp
		if fields[2] == "0" {
			findings = append(findings, audit.Finding{
				ID:       "vpn-handshake-" + fields[1][:8],
				CheckID:  "vpn",
				Severity: audit.SeverityWarn,
				Title:    fmt.Sprintf("Peer %s... never completed handshake", fields[1][:8]),
			})
		}
	}

	if len(findings) == 0 {
		findings = append(findings, audit.Finding{
			ID:       "vpn-handshakes",
			CheckID:  "vpn",
			Severity: audit.SeverityPass,
			Title:    "All WireGuard peers have recent handshakes",
		})
	}

	return findings
}

func sanitize(s string) string {
	r := strings.NewReplacer("/", "-", ".", "-", "*", "")
	result := r.Replace(s)
	if len(result) > 0 && result[0] == '-' {
		result = result[1:]
	}
	return result
}
