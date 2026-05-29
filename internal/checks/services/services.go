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

		severity, title, remediation := classifyPort(svc.port)

		findings = append(findings, audit.Finding{
			ID:          fmt.Sprintf("services-exposed-%s", svc.port),
			CheckID:     "services",
			Severity:    severity,
			Title:       title,
			Evidence:    fmt.Sprintf("Address: %s, Process: %s", svc.address, svc.process),
			Remediation: remediation,
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

type portInfo struct {
	name        string
	severity    audit.Severity
	remediation string
}

var knownPorts = map[string]portInfo{
	// Kubernetes
	"6443":  {name: "Kubernetes API server", severity: audit.SeverityWarn, remediation: "Restrict access to the API server via VPN or firewall rules"},
	"10250": {name: "Kubelet API", severity: audit.SeverityWarn, remediation: "Kubelet should not be publicly accessible. Bind to internal interface or use firewall"},
	"10251": {name: "Kubernetes scheduler", severity: audit.SeverityWarn, remediation: "Bind to internal interface"},
	"10252": {name: "Kubernetes controller manager", severity: audit.SeverityWarn, remediation: "Bind to internal interface"},
	"8443":  {name: "Kubernetes dashboard / HTTPS alt", severity: audit.SeverityWarn, remediation: "Verify if this needs public access. Consider VPN"},
	"2379":  {name: "etcd", severity: audit.SeverityFail, remediation: "etcd must not be publicly accessible. Bind to 127.0.0.1"},
	"2380":  {name: "etcd peer", severity: audit.SeverityFail, remediation: "etcd peer port must not be publicly accessible"},
	// DNS
	"53": {name: "DNS (CoreDNS/dnsmasq)", severity: audit.SeverityInfo, remediation: "DNS is commonly exposed. Verify this is intentional"},
	// Monitoring
	"9090":  {name: "Prometheus", severity: audit.SeverityWarn, remediation: "Prometheus should be behind VPN or authentication"},
	"9100":  {name: "Prometheus node-exporter", severity: audit.SeverityWarn, remediation: "Node-exporter exposes system metrics. Restrict to internal network"},
	"3000":  {name: "Grafana", severity: audit.SeverityWarn, remediation: "Grafana should be behind VPN or have authentication enabled"},
	"9093":  {name: "Alertmanager", severity: audit.SeverityWarn, remediation: "Alertmanager should be behind VPN"},
	// Databases (high risk)
	"3306":  {name: "MySQL", severity: audit.SeverityFail, remediation: "Bind MySQL to 127.0.0.1 or use firewall rules"},
	"5432":  {name: "PostgreSQL", severity: audit.SeverityFail, remediation: "Bind PostgreSQL to 127.0.0.1 or use firewall rules"},
	"6379":  {name: "Redis", severity: audit.SeverityFail, remediation: "Bind Redis to 127.0.0.1 or use firewall rules"},
	"27017": {name: "MongoDB", severity: audit.SeverityFail, remediation: "Bind MongoDB to 127.0.0.1 or use firewall rules"},
	"9200":  {name: "Elasticsearch", severity: audit.SeverityFail, remediation: "Elasticsearch must not be publicly accessible"},
	"11211": {name: "Memcached", severity: audit.SeverityFail, remediation: "Memcached must not be publicly accessible"},
	// Docker
	"2375": {name: "Docker API (unencrypted)", severity: audit.SeverityCritical, remediation: "Docker API without TLS is extremely dangerous. Disable immediately"},
	"2376": {name: "Docker API (TLS)", severity: audit.SeverityFail, remediation: "Docker API should not be publicly accessible even with TLS"},
}

func classifyPort(port string) (audit.Severity, string, string) {
	if info, ok := knownPorts[port]; ok {
		return info.severity, fmt.Sprintf("%s exposed (port %s)", info.name, port), info.remediation
	}
	return audit.SeverityWarn,
		fmt.Sprintf("Unknown service exposed on port %s", port),
		fmt.Sprintf("Verify if port %s needs to be publicly accessible. Consider binding to 127.0.0.1 or using a VPN.", port)
}
