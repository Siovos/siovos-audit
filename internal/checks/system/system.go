package system

import (
	"context"
	"fmt"
	"strings"

	"github.com/Siovos/siovos-audit/pkg/audit"
	"github.com/Siovos/siovos-audit/pkg/collector"
)

type Check struct{}

func New() *Check { return &Check{} }

func (c *Check) ID() string       { return "system" }
func (c *Check) Name() string     { return "System" }
func (c *Check) Category() string { return "system" }

func (c *Check) Run(ctx context.Context, col collector.Collector) ([]audit.Finding, error) {
	var findings []audit.Finding

	findings = append(findings, checkUpdates(ctx, col)...)
	findings = append(findings, checkUnattendedUpgrades(ctx, col)...)
	findings = append(findings, checkSensitivePermissions(ctx, col)...)
	findings = append(findings, checkKernelHardening(ctx, col)...)
	findings = append(findings, checkCoreDumps(ctx, col)...)
	findings = append(findings, checkMountOptions(ctx, col)...)
	findings = append(findings, checkUmask(ctx, col)...)
	findings = append(findings, checkMACFramework(ctx, col)...)

	return findings, nil
}

func checkUpdates(ctx context.Context, col collector.Collector) []audit.Finding {
	// Check for available security updates (Debian/Ubuntu)
	out, err := col.Exec(ctx, "apt list --upgradable 2>/dev/null | grep -i security | wc -l")
	if err == nil {
		count := strings.TrimSpace(string(out))
		if count != "0" && count != "" {
			return []audit.Finding{{
				ID:          "system-updates",
				CheckID:     "system",
				Severity:    audit.SeverityWarn,
				Title:       fmt.Sprintf("%s security updates available", count),
				Remediation: "Run: apt update && apt upgrade",
			}}
		}
		return []audit.Finding{{
			ID:       "system-updates",
			CheckID:  "system",
			Severity: audit.SeverityPass,
			Title:    "No pending security updates",
		}}
	}

	// Try RHEL/CentOS
	out, err = col.Exec(ctx, "yum check-update --security 2>/dev/null | tail -1")
	if err == nil && strings.TrimSpace(string(out)) != "" {
		return []audit.Finding{{
			ID:       "system-updates",
			CheckID:  "system",
			Severity: audit.SeverityInfo,
			Title:    "Update check: " + strings.TrimSpace(string(out)),
		}}
	}

	return []audit.Finding{{
		ID:       "system-updates",
		CheckID:  "system",
		Severity: audit.SeverityInfo,
		Title:    "Could not check for updates (unsupported package manager)",
	}}
}

func checkUnattendedUpgrades(ctx context.Context, col collector.Collector) []audit.Finding {
	// Debian/Ubuntu
	out, err := col.Exec(ctx, "dpkg -l unattended-upgrades 2>/dev/null | grep '^ii'")
	if err == nil && strings.Contains(string(out), "unattended-upgrades") {
		// Check if enabled
		out2, err2 := col.Exec(ctx, "cat /etc/apt/apt.conf.d/20auto-upgrades 2>/dev/null")
		if err2 == nil && strings.Contains(string(out2), `"1"`) {
			return []audit.Finding{{
				ID:       "system-unattended",
				CheckID:  "system",
				Severity: audit.SeverityPass,
				Title:    "Unattended upgrades enabled",
			}}
		}
		return []audit.Finding{{
			ID:          "system-unattended",
			CheckID:     "system",
			Severity:    audit.SeverityWarn,
			Title:       "Unattended upgrades installed but not enabled",
			Remediation: "Enable in /etc/apt/apt.conf.d/20auto-upgrades",
		}}
	}

	return []audit.Finding{{
		ID:          "system-unattended",
		CheckID:     "system",
		Severity:    audit.SeverityWarn,
		Title:       "Automatic security updates not configured",
		Remediation: "Install unattended-upgrades: apt install unattended-upgrades",
	}}
}

func checkSensitivePermissions(ctx context.Context, col collector.Collector) []audit.Finding {
	checks := []struct {
		path     string
		maxPerms string
		name     string
	}{
		{"/etc/shadow", "640", "shadow file"},
		{"/etc/gshadow", "640", "gshadow file"},
		{"/etc/passwd", "644", "passwd file"},
		{"/root/.ssh", "700", "root SSH directory"},
	}

	var findings []audit.Finding
	for _, c := range checks {
		out, err := col.Exec(ctx, fmt.Sprintf("stat -c '%%a' %s 2>/dev/null", c.path))
		if err != nil {
			continue
		}
		perms := strings.TrimSpace(string(out))
		if permsOK(perms, c.maxPerms) {
			findings = append(findings, audit.Finding{
				ID:       fmt.Sprintf("system-perms-%s", strings.ReplaceAll(c.path, "/", "-")[1:]),
				CheckID:  "system",
				Severity: audit.SeverityPass,
				Title:    fmt.Sprintf("Permissions OK: %s (%s)", c.name, perms),
			})
		} else {
			findings = append(findings, audit.Finding{
				ID:          fmt.Sprintf("system-perms-%s", strings.ReplaceAll(c.path, "/", "-")[1:]),
				CheckID:     "system",
				Severity:    audit.SeverityFail,
				Title:       fmt.Sprintf("Permissions too open: %s (%s)", c.name, perms),
				Remediation: fmt.Sprintf("chmod %s %s", c.maxPerms, c.path),
				References:  []string{"CIS 6.1"},
			})
		}
	}

	return findings
}

func checkKernelHardening(ctx context.Context, col collector.Collector) []audit.Finding {
	params := []struct {
		key      string
		expected string
		title    string
		ref      string
	}{
		{"net.ipv4.conf.all.rp_filter", "1", "Reverse path filtering enabled", "CIS 3.3.7"},
		{"net.ipv4.conf.all.accept_redirects", "0", "ICMP redirects disabled", "CIS 3.3.2"},
		{"net.ipv4.conf.all.send_redirects", "0", "Send redirects disabled", "CIS 3.3.1"},
		{"kernel.randomize_va_space", "2", "ASLR enabled", "CIS 1.5.2"},
	}

	var findings []audit.Finding
	for _, p := range params {
		out, err := col.Exec(ctx, fmt.Sprintf("sysctl -n %s 2>/dev/null", p.key))
		if err != nil {
			continue
		}
		val := strings.TrimSpace(string(out))
		if val == p.expected {
			findings = append(findings, audit.Finding{
				ID:       "system-sysctl-" + strings.ReplaceAll(p.key, ".", "-"),
				CheckID:  "system",
				Severity: audit.SeverityPass,
				Title:    p.title,
			})
		} else {
			findings = append(findings, audit.Finding{
				ID:          "system-sysctl-" + strings.ReplaceAll(p.key, ".", "-"),
				CheckID:     "system",
				Severity:    audit.SeverityWarn,
				Title:       fmt.Sprintf("%s = %s (expected %s)", p.key, val, p.expected),
				Remediation: fmt.Sprintf("Set %s = %s in /etc/sysctl.conf", p.key, p.expected),
				References:  []string{p.ref},
			})
		}
	}

	return findings
}

func checkCoreDumps(ctx context.Context, col collector.Collector) []audit.Finding {
	out, err := col.Exec(ctx, "sysctl -n fs.suid_dumpable 2>/dev/null")
	if err != nil {
		return nil
	}
	val := strings.TrimSpace(string(out))
	if val == "0" {
		return []audit.Finding{{
			ID: "system-core-dumps", CheckID: "system",
			Severity: audit.SeverityPass,
			Title:    "Core dumps disabled for SUID binaries",
		}}
	}
	return []audit.Finding{{
		ID: "system-core-dumps", CheckID: "system",
		Severity:    audit.SeverityWarn,
		Title:       "Core dumps enabled for SUID binaries",
		Remediation: "Set fs.suid_dumpable = 0 in /etc/sysctl.conf",
		References:  []string{"CIS 1.5.1"},
	}}
}

func checkMountOptions(ctx context.Context, col collector.Collector) []audit.Finding {
	out, err := col.Exec(ctx, "mount | grep ' /tmp '")
	if err != nil || strings.TrimSpace(string(out)) == "" {
		return []audit.Finding{{
			ID: "system-tmp-partition", CheckID: "system",
			Severity: audit.SeverityInfo,
			Title:    "/tmp not a separate partition",
		}}
	}

	var findings []audit.Finding
	mountLine := string(out)
	findings = append(findings, audit.Finding{
		ID: "system-tmp-partition", CheckID: "system",
		Severity: audit.SeverityPass,
		Title:    "/tmp is a separate mount",
	})

	if !strings.Contains(mountLine, "noexec") {
		findings = append(findings, audit.Finding{
			ID: "system-tmp-noexec", CheckID: "system",
			Severity:    audit.SeverityWarn,
			Title:       "/tmp not mounted with noexec",
			Remediation: "Add noexec to /tmp mount options in /etc/fstab",
			References:  []string{"CIS 1.1.4"},
		})
	}
	if !strings.Contains(mountLine, "nosuid") {
		findings = append(findings, audit.Finding{
			ID: "system-tmp-nosuid", CheckID: "system",
			Severity:    audit.SeverityWarn,
			Title:       "/tmp not mounted with nosuid",
			Remediation: "Add nosuid to /tmp mount options in /etc/fstab",
			References:  []string{"CIS 1.1.5"},
		})
	}

	return findings
}

func checkUmask(ctx context.Context, col collector.Collector) []audit.Finding {
	out, err := col.Exec(ctx, "grep -E '^\\s*UMASK' /etc/login.defs 2>/dev/null")
	if err != nil {
		return nil
	}
	line := strings.TrimSpace(string(out))
	if strings.Contains(line, "027") || strings.Contains(line, "077") {
		return []audit.Finding{{
			ID: "system-umask", CheckID: "system",
			Severity: audit.SeverityPass,
			Title:    "Default umask is restrictive: " + line,
		}}
	}
	return []audit.Finding{{
		ID: "system-umask", CheckID: "system",
		Severity:    audit.SeverityWarn,
		Title:       "Default umask not restrictive: " + line,
		Remediation: "Set UMASK 027 in /etc/login.defs",
		References:  []string{"CIS 5.5.5"},
	}}
}

func checkMACFramework(ctx context.Context, col collector.Collector) []audit.Finding {
	// Check AppArmor
	out, err := col.Exec(ctx, "aa-status --enabled 2>/dev/null && echo enabled")
	if err == nil && strings.Contains(string(out), "enabled") {
		return []audit.Finding{{
			ID: "system-mac", CheckID: "system",
			Severity: audit.SeverityPass,
			Title:    "AppArmor enabled",
		}}
	}
	// Check SELinux
	out, err = col.Exec(ctx, "getenforce 2>/dev/null")
	if err == nil {
		mode := strings.TrimSpace(string(out))
		if mode == "Enforcing" || mode == "Permissive" {
			return []audit.Finding{{
				ID: "system-mac", CheckID: "system",
				Severity: audit.SeverityPass,
				Title:    "SELinux " + mode,
			}}
		}
	}
	return []audit.Finding{{
		ID: "system-mac", CheckID: "system",
		Severity:    audit.SeverityWarn,
		Title:       "No MAC framework (AppArmor/SELinux) active",
		Remediation: "Enable AppArmor or SELinux",
		References:  []string{"CIS 1.6"},
	}}
}

func permsOK(actual, max string) bool {
	if len(actual) != 3 || len(max) != 3 {
		return false
	}
	for i := 0; i < 3; i++ {
		if actual[i] > max[i] {
			return false
		}
	}
	return true
}
