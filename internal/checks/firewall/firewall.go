package firewall

import (
	"context"
	"fmt"
	"strings"

	"github.com/Siovos/siovos-audit/pkg/audit"
	"github.com/Siovos/siovos-audit/pkg/collector"
)

type Check struct{}

func New() *Check { return &Check{} }

func (c *Check) ID() string       { return "firewall" }
func (c *Check) Name() string     { return "Firewall" }
func (c *Check) Category() string { return "firewall" }

func (c *Check) Run(ctx context.Context, col collector.Collector) ([]audit.Finding, error) {
	var findings []audit.Finding

	findings = append(findings, checkUFWStatus(ctx, col)...)
	findings = append(findings, checkDefaultPolicy(ctx, col)...)
	findings = append(findings, checkOpenPorts(ctx, col)...)

	return findings, nil
}

func checkUFWStatus(ctx context.Context, col collector.Collector) []audit.Finding {
	out, err := col.Exec(ctx, "ufw status 2>/dev/null || iptables -L -n 2>/dev/null | head -5")
	if err != nil {
		return []audit.Finding{{
			ID:          "firewall-active",
			CheckID:     "firewall",
			Severity:    audit.SeverityFail,
			Title:       "No firewall detected",
			Evidence:    err.Error(),
			Remediation: "Install and enable UFW: apt install ufw && ufw enable",
		}}
	}

	output := string(out)

	if strings.Contains(output, "Status: active") {
		return []audit.Finding{{
			ID:       "firewall-active",
			CheckID:  "firewall",
			Severity: audit.SeverityPass,
			Title:    "UFW active",
			Evidence: "Status: active",
		}}
	}

	if strings.Contains(output, "Chain INPUT") {
		return []audit.Finding{{
			ID:       "firewall-active",
			CheckID:  "firewall",
			Severity: audit.SeverityInfo,
			Title:    "iptables rules detected (UFW not active)",
			Evidence: strings.TrimSpace(output),
		}}
	}

	return []audit.Finding{{
		ID:          "firewall-active",
		CheckID:     "firewall",
		Severity:    audit.SeverityFail,
		Title:       "Firewall not active",
		Evidence:    strings.TrimSpace(output),
		Remediation: "Enable UFW: ufw enable",
	}}
}

func checkDefaultPolicy(ctx context.Context, col collector.Collector) []audit.Finding {
	out, err := col.Exec(ctx, "ufw status verbose 2>/dev/null")
	if err != nil {
		return nil
	}

	output := string(out)
	if !strings.Contains(output, "Status: active") {
		return nil
	}

	f := audit.Finding{
		ID:      "firewall-default-deny",
		CheckID: "firewall",
	}

	if strings.Contains(output, "Default: deny (incoming)") {
		f.Severity = audit.SeverityPass
		f.Title = "Default deny incoming"
		f.Evidence = "Default: deny (incoming)"
	} else {
		f.Severity = audit.SeverityFail
		f.Title = "Default policy is not deny incoming"
		f.Remediation = "Set default deny: ufw default deny incoming"
		f.Evidence = output
	}

	return []audit.Finding{f}
}

func checkOpenPorts(ctx context.Context, col collector.Collector) []audit.Finding {
	facts := audit.GetFacts(ctx)

	out, err := col.Exec(ctx, "ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null")
	if err != nil {
		return nil
	}

	lines := strings.Split(string(out), "\n")
	var publicPorts []string

	for _, line := range lines[1:] {
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		addr := fields[3]
		if !strings.HasPrefix(addr, "127.") && !strings.HasPrefix(addr, "::1") && addr != "0.0.0.0:22" && addr != "*:22" {
			if parts := strings.Split(addr, ":"); len(parts) > 0 {
				port := parts[len(parts)-1]
				publicPorts = append(publicPorts, port)
			}
		}
	}

	commonPorts := map[string]bool{"22": true, "80": true, "443": true}
	var findings []audit.Finding

	for _, port := range publicPorts {
		if commonPorts[port] {
			continue
		}

		// Use Facts to determine if port is truly public
		if facts != nil && !facts.IsPortPublic(port) {
			findings = append(findings, audit.Finding{
				ID:       fmt.Sprintf("firewall-open-port-%s", port),
				CheckID:  "firewall",
				Severity: audit.SeverityPass,
				Title:    fmt.Sprintf("Port %s%s listening but blocked by firewall", port, identifyPort(port)),
				Evidence: fmt.Sprintf("Port %s is listening but UFW has no public allow rule", port),
			})
			continue
		}

		name := identifyPort(port)
		findings = append(findings, audit.Finding{
			ID:       fmt.Sprintf("firewall-open-port-%s", port),
			CheckID:  "firewall",
			Severity: audit.SeverityWarn,
			Title:    fmt.Sprintf("Port %s open%s - publicly accessible", port, name),
			Evidence: fmt.Sprintf("Port %s is listening and allowed through firewall", port),
		})
	}

	if len(findings) == 0 {
		findings = append(findings, audit.Finding{
			ID:       "firewall-open-ports",
			CheckID:  "firewall",
			Severity: audit.SeverityPass,
			Title:    "No unexpected open ports",
		})
	}

	return findings
}

var portNames = map[string]string{
	"53":    "DNS",
	"6443":  "Kubernetes API",
	"8443":  "HTTPS alt / K8s dashboard",
	"10250": "Kubelet",
	"10251": "K8s scheduler",
	"10252": "K8s controller",
	"9090":  "Prometheus",
	"9100":  "Node exporter",
	"3000":  "Grafana",
	"5432":  "PostgreSQL",
	"3306":  "MySQL",
	"6379":  "Redis",
	"27017": "MongoDB",
	"2375":  "Docker API",
	"2376":  "Docker API TLS",
	"9200":  "Elasticsearch",
}

func identifyPort(port string) string {
	if name, ok := portNames[port]; ok {
		return " (" + name + ")"
	}
	return ""
}
