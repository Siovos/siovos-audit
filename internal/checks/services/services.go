package services

import (
	"context"
	"fmt"
	"strings"

	"github.com/Siovos/siovos-audit/pkg/audit"
	"github.com/Siovos/siovos-audit/pkg/collector"
)

type Check struct{}

func New() *Check { return &Check{} }

func (c *Check) ID() string       { return "services" }
func (c *Check) Name() string     { return "Exposed Services" }
func (c *Check) Category() string { return "services" }

func (c *Check) Run(ctx context.Context, col collector.Collector) ([]audit.Finding, error) {
	var findings []audit.Finding

	findings = append(findings, checkListeningServices(ctx, col)...)
	findings = append(findings, checkDefaultCredentials(ctx, col)...)

	return findings, nil
}

func checkListeningServices(ctx context.Context, col collector.Collector) []audit.Finding {
	out, err := col.Exec(ctx, "ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null")
	if err != nil {
		return []audit.Finding{{
			ID:       "services-listen",
			CheckID:  "services",
			Severity: audit.SeverityWarn,
			Title:    "Could not list listening services",
			Evidence: err.Error(),
		}}
	}

	lines := strings.Split(string(out), "\n")
	var publicServices []serviceInfo

	for _, line := range lines[1:] {
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		addr := fields[3]
		if isPublicAddress(addr) {
			port := extractPort(addr)
			process := ""
			if len(fields) >= 6 {
				process = fields[len(fields)-1]
			}
			publicServices = append(publicServices, serviceInfo{
				port:    port,
				address: addr,
				process: process,
			})
		}
	}

	var findings []audit.Finding
	expectedPorts := map[string]bool{"22": true, "80": true, "443": true}

	for _, svc := range publicServices {
		if expectedPorts[svc.port] {
			continue
		}

		severity := audit.SeverityWarn
		title := fmt.Sprintf("Service exposed on port %s", svc.port)

		if isHighRiskPort(svc.port) {
			severity = audit.SeverityFail
			title = fmt.Sprintf("High-risk service exposed on port %s", svc.port)
		}

		findings = append(findings, audit.Finding{
			ID:       fmt.Sprintf("services-exposed-%s", svc.port),
			CheckID:  "services",
			Severity: severity,
			Title:    title,
			Evidence: fmt.Sprintf("Address: %s, Process: %s", svc.address, svc.process),
			Remediation: fmt.Sprintf("Verify if port %s needs to be publicly accessible. Consider binding to 127.0.0.1 or using a VPN.", svc.port),
		})
	}

	if len(findings) == 0 {
		findings = append(findings, audit.Finding{
			ID:       "services-exposed",
			CheckID:  "services",
			Severity: audit.SeverityPass,
			Title:    "No unexpected services exposed",
		})
	}

	return findings
}

func checkDefaultCredentials(ctx context.Context, col collector.Collector) []audit.Finding {
	// Check for common services with known default ports that might have default creds
	dangerousServices := map[string]string{
		"3306": "MySQL",
		"5432": "PostgreSQL",
		"6379": "Redis",
		"27017": "MongoDB",
	}

	out, err := col.Exec(ctx, "ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null")
	if err != nil {
		return nil
	}

	var findings []audit.Finding
	output := string(out)

	for port, name := range dangerousServices {
		if strings.Contains(output, ":"+port) {
			// Check if bound to public interface
			if strings.Contains(output, "0.0.0.0:"+port) || strings.Contains(output, ":::"+port) {
				findings = append(findings, audit.Finding{
					ID:          fmt.Sprintf("services-db-public-%s", port),
					CheckID:     "services",
					Severity:    audit.SeverityFail,
					Title:       fmt.Sprintf("%s accessible on public interface (port %s)", name, port),
					Remediation: fmt.Sprintf("Bind %s to 127.0.0.1 or use firewall rules to restrict access", name),
				})
			}
		}
	}

	return findings
}

type serviceInfo struct {
	port    string
	address string
	process string
}

func isPublicAddress(addr string) bool {
	return !strings.HasPrefix(addr, "127.") &&
		!strings.HasPrefix(addr, "::1") &&
		!strings.HasPrefix(addr, "[::1]")
}

func extractPort(addr string) string {
	parts := strings.Split(addr, ":")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return ""
}

func isHighRiskPort(port string) bool {
	highRisk := map[string]bool{
		"3306":  true, // MySQL
		"5432":  true, // PostgreSQL
		"6379":  true, // Redis
		"27017": true, // MongoDB
		"9200":  true, // Elasticsearch
		"11211": true, // Memcached
		"2375":  true, // Docker API
		"2376":  true, // Docker API TLS
	}
	return highRisk[port]
}
