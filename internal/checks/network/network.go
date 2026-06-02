package network

import (
	"context"
	"fmt"
	"strings"

	"github.com/Siovos/siovos-audit/pkg/audit"
	"github.com/Siovos/siovos-audit/pkg/collector"
)

type Check struct{}

func New() *Check { return &Check{} }

func (c *Check) ID() string       { return "network" }
func (c *Check) Name() string     { return "Network" }
func (c *Check) Category() string { return "network" }

func (c *Check) Run(ctx context.Context, col collector.Collector) ([]audit.Finding, error) {
	var findings []audit.Finding

	findings = append(findings, checkDNS(ctx, col)...)
	findings = append(findings, checkIPv6(ctx, col)...)
	findings = append(findings, checkListeningServices(ctx, col)...)
	findings = append(findings, checkIPForwarding(ctx, col)...)
	findings = append(findings, checkSYNCookies(ctx, col)...)
	findings = append(findings, checkPromiscuous(ctx, col)...)

	return findings, nil
}

func checkDNS(ctx context.Context, col collector.Collector) []audit.Finding {
	out, err := col.ReadFile(ctx, "/etc/resolv.conf")
	if err != nil {
		return []audit.Finding{{
			ID:       "network-dns",
			CheckID:  "network",
			Severity: audit.SeverityInfo,
			Title:    "Could not read /etc/resolv.conf",
		}}
	}

	var nameservers []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "nameserver") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				nameservers = append(nameservers, fields[1])
			}
		}
	}

	if len(nameservers) == 0 {
		return []audit.Finding{{
			ID:          "network-dns",
			CheckID:     "network",
			Severity:    audit.SeverityWarn,
			Title:       "No DNS nameservers configured",
			Remediation: "Configure nameservers in /etc/resolv.conf",
		}}
	}

	return []audit.Finding{{
		ID:       "network-dns",
		CheckID:  "network",
		Severity: audit.SeverityPass,
		Title:    fmt.Sprintf("DNS configured: %s", strings.Join(nameservers, ", ")),
	}}
}

func checkIPv6(ctx context.Context, col collector.Collector) []audit.Finding {
	out, err := col.Exec(ctx, "sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null")
	if err != nil {
		return nil
	}

	val := strings.TrimSpace(string(out))
	if val == "1" {
		return []audit.Finding{{
			ID:       "network-ipv6",
			CheckID:  "network",
			Severity: audit.SeverityPass,
			Title:    "IPv6 disabled",
		}}
	}

	// IPv6 is enabled — check if firewall covers it
	out, err = col.Exec(ctx, "ip6tables -L -n 2>/dev/null | head -5")
	if err != nil || !strings.Contains(string(out), "Chain") {
		return []audit.Finding{{
			ID:          "network-ipv6",
			CheckID:     "network",
			Severity:    audit.SeverityWarn,
			Title:       "IPv6 enabled but no ip6tables rules",
			Remediation: "Either disable IPv6 or configure ip6tables rules",
		}}
	}

	return []audit.Finding{{
		ID:       "network-ipv6",
		CheckID:  "network",
		Severity: audit.SeverityInfo,
		Title:    "IPv6 enabled with ip6tables rules",
	}}
}

func checkListeningServices(ctx context.Context, col collector.Collector) []audit.Finding {
	out, err := col.Exec(ctx, "ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null")
	if err != nil {
		return nil
	}

	lines := strings.Split(string(out), "\n")
	total := 0
	public := 0

	for _, line := range lines[1:] {
		if line == "" {
			continue
		}
		total++
		fields := strings.Fields(line)
		if len(fields) >= 4 {
			addr := fields[3]
			if !strings.HasPrefix(addr, "127.") && !strings.HasPrefix(addr, "::1") && !strings.HasPrefix(addr, "[::1]") {
				public++
			}
		}
	}

	findings := []audit.Finding{{
		ID:       "network-services-count",
		CheckID:  "network",
		Severity: audit.SeverityInfo,
		Title:    fmt.Sprintf("%d listening services (%d on public interfaces)", total, public),
	}}

	if public > 10 {
		findings = append(findings, audit.Finding{
			ID:          "network-services-many",
			CheckID:     "network",
			Severity:    audit.SeverityWarn,
			Title:       fmt.Sprintf("High number of public services: %d", public),
			Remediation: "Review listening services and disable unnecessary ones",
		})
	}

	return findings
}

func checkIPForwarding(ctx context.Context, col collector.Collector) []audit.Finding {
	out, err := col.Exec(ctx, "sysctl -n net.ipv4.ip_forward 2>/dev/null")
	if err != nil {
		return nil
	}
	val := strings.TrimSpace(string(out))
	if val == "0" {
		return []audit.Finding{{
			ID: "network-ip-forward", CheckID: "network",
			Severity: audit.SeverityPass,
			Title:    "IP forwarding disabled",
		}}
	}
	// IP forwarding enabled — could be intentional (Docker, K8s, VPN)
	return []audit.Finding{{
		ID: "network-ip-forward", CheckID: "network",
		Severity: audit.SeverityInfo,
		Title:    "IP forwarding enabled (expected if running containers, K8s, or VPN)",
		Evidence: "net.ipv4.ip_forward=1",
	}}
}

func checkSYNCookies(ctx context.Context, col collector.Collector) []audit.Finding {
	out, err := col.Exec(ctx, "sysctl -n net.ipv4.tcp_syncookies 2>/dev/null")
	if err != nil {
		return nil
	}
	val := strings.TrimSpace(string(out))
	if val == "1" {
		return []audit.Finding{{
			ID: "network-syn-cookies", CheckID: "network",
			Severity: audit.SeverityPass,
			Title:    "TCP SYN cookies enabled",
		}}
	}
	return []audit.Finding{{
		ID: "network-syn-cookies", CheckID: "network",
		Severity:    audit.SeverityWarn,
		Title:       "TCP SYN cookies disabled",
		Remediation: "Set net.ipv4.tcp_syncookies = 1 in /etc/sysctl.conf",
		References:  []string{"CIS 3.3.8"},
	}}
}

func checkPromiscuous(ctx context.Context, col collector.Collector) []audit.Finding {
	out, err := col.Exec(ctx, "ip link show 2>/dev/null | grep PROMISC")
	if err != nil || strings.TrimSpace(string(out)) == "" {
		return []audit.Finding{{
			ID: "network-promiscuous", CheckID: "network",
			Severity: audit.SeverityPass,
			Title:    "No promiscuous interfaces",
		}}
	}
	return []audit.Finding{{
		ID: "network-promiscuous", CheckID: "network",
		Severity: audit.SeverityWarn,
		Title:    "Promiscuous interface detected (possible network sniffing)",
		Evidence: strings.TrimSpace(string(out)),
	}}
}
