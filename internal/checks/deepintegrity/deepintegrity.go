package deepintegrity

import (
	"context"
	"fmt"
	"strings"

	"github.com/Siovos/siovos-audit/pkg/audit"
	"github.com/Siovos/siovos-audit/pkg/collector"
)

type Check struct{}

func New() *Check { return &Check{} }

func (c *Check) ID() string       { return "deepintegrity" }
func (c *Check) Name() string     { return "Deep Integrity" }
func (c *Check) Category() string { return "deepintegrity" }

func (c *Check) Run(ctx context.Context, col collector.Collector) ([]audit.Finding, error) {
	var findings []audit.Finding

	findings = append(findings, checkOrphanBinaries(ctx, col)...)
	findings = append(findings, checkPackageIntegrity(ctx, col)...)
	findings = append(findings, checkHiddenProcesses(ctx, col)...)
	findings = append(findings, checkHiddenPorts(ctx, col)...)
	findings = append(findings, checkOutboundConnections(ctx, col)...)
	findings = append(findings, checkRootkitSignatures(ctx, col)...)
	findings = append(findings, checkKernelModules(ctx, col)...)
	findings = append(findings, checkHiddenFiles(ctx, col)...)
	findings = append(findings, checkRkhunterWrapper(ctx, col)...)

	if len(findings) == 0 {
		findings = append(findings, audit.Finding{
			ID: "deep-clean", CheckID: "deepintegrity",
			Severity: audit.SeverityPass,
			Title:    "No integrity issues detected",
		})
	}

	return findings, nil
}

// checkOrphanBinaries finds executables not belonging to any package that are currently running.
func checkOrphanBinaries(ctx context.Context, col collector.Collector) []audit.Finding {
	// Get all running binary paths
	out, err := col.Exec(ctx, "ps -eo comm= | sort -u")
	if err != nil {
		return nil
	}

	procs := strings.Split(strings.TrimSpace(string(out)), "\n")
	var orphans []string

	for _, proc := range procs {
		proc = strings.TrimSpace(proc)
		if proc == "" || strings.HasPrefix(proc, "[") { // kernel threads
			continue
		}

		// Find the full path
		pathOut, err := col.Exec(ctx, fmt.Sprintf("which %q 2>/dev/null", proc))
		if err != nil || strings.TrimSpace(string(pathOut)) == "" {
			continue
		}
		binPath := strings.TrimSpace(string(pathOut))

		// Check if it belongs to a package
		pkgOut, err := col.Exec(ctx, fmt.Sprintf("dpkg -S %q 2>/dev/null || rpm -qf %q 2>/dev/null", binPath, binPath))
		if err != nil || strings.Contains(string(pkgOut), "no path found") || strings.Contains(string(pkgOut), "not owned") || strings.TrimSpace(string(pkgOut)) == "" {
			// Known legitimate non-package binaries
			if isKnownOrphan(binPath) {
				continue
			}
			orphans = append(orphans, fmt.Sprintf("%s (%s)", proc, binPath))
		}
	}

	if len(orphans) == 0 {
		return []audit.Finding{{
			ID: "deep-orphan-binaries", CheckID: "deepintegrity",
			Severity: audit.SeverityPass,
			Title:    "All running binaries belong to known packages",
		}}
	}

	severity := audit.SeverityInfo
	if len(orphans) > 5 {
		severity = audit.SeverityWarn
	}

	return []audit.Finding{{
		ID: "deep-orphan-binaries", CheckID: "deepintegrity",
		Severity: severity,
		Title:    fmt.Sprintf("Running binaries not from packages (%d)", len(orphans)),
		Evidence: strings.Join(orphans, "\n"),
	}}
}

// checkPackageIntegrity verifies installed files haven't been modified.
func checkPackageIntegrity(ctx context.Context, col collector.Collector) []audit.Finding {
	// Try dpkg -V (Debian/Ubuntu)
	out, err := col.Exec(ctx, "dpkg -V 2>/dev/null | head -20")
	if err == nil && strings.TrimSpace(string(out)) != "" {
		lines := strings.Split(strings.TrimSpace(string(out)), "\n")
		// Filter out expected modifications (configs, etc.)
		var suspicious []string
		for _, line := range lines {
			// dpkg -V shows: ??5?????? c /etc/... for config files (expected)
			// Suspicious: modifications to binaries
			if strings.Contains(line, "/usr/bin/") || strings.Contains(line, "/usr/sbin/") || strings.Contains(line, "/bin/") || strings.Contains(line, "/sbin/") {
				suspicious = append(suspicious, line)
			}
		}

		if len(suspicious) > 0 {
			return []audit.Finding{{
				ID: "deep-pkg-integrity", CheckID: "deepintegrity",
				Severity:    audit.SeverityFail,
				Title:       fmt.Sprintf("Modified system binaries detected (%d)", len(suspicious)),
				Evidence:    strings.Join(suspicious, "\n"),
				Remediation: "Reinstall affected packages: apt install --reinstall <package>",
			}}
		}
		return []audit.Finding{{
			ID: "deep-pkg-integrity", CheckID: "deepintegrity",
			Severity: audit.SeverityPass,
			Title:    "Package integrity verified (dpkg -V)",
		}}
	}

	// Try rpm -Va (RHEL/CentOS)
	out, err = col.Exec(ctx, "rpm -Va --nomtime 2>/dev/null | grep -E '^..5' | grep -E '/usr/bin/|/usr/sbin/|/bin/|/sbin/' | head -20")
	if err == nil && strings.TrimSpace(string(out)) != "" {
		lines := strings.Split(strings.TrimSpace(string(out)), "\n")
		return []audit.Finding{{
			ID: "deep-pkg-integrity", CheckID: "deepintegrity",
			Severity:    audit.SeverityFail,
			Title:       fmt.Sprintf("Modified system binaries detected (%d)", len(lines)),
			Evidence:    strings.TrimSpace(string(out)),
			Remediation: "Reinstall affected packages: yum reinstall <package>",
		}}
	}

	return []audit.Finding{{
		ID: "deep-pkg-integrity", CheckID: "deepintegrity",
		Severity: audit.SeverityPass,
		Title:    "No modified system binaries detected",
	}}
}

// checkHiddenProcesses compares ps output with /proc to find hidden processes.
func checkHiddenProcesses(ctx context.Context, col collector.Collector) []audit.Finding {
	// Count processes via ps
	psOut, err := col.Exec(ctx, "ps -e --no-headers | wc -l")
	if err != nil {
		return nil
	}
	// Count processes via /proc
	procOut, err := col.Exec(ctx, "ls -d /proc/[0-9]* 2>/dev/null | wc -l")
	if err != nil {
		return nil
	}

	psCount := strings.TrimSpace(string(psOut))
	procCount := strings.TrimSpace(string(procOut))

	if psCount == procCount {
		return []audit.Finding{{
			ID: "deep-hidden-procs", CheckID: "deepintegrity",
			Severity: audit.SeverityPass,
			Title:    fmt.Sprintf("No hidden processes (ps=%s, /proc=%s)", psCount, procCount),
		}}
	}

	return []audit.Finding{{
		ID: "deep-hidden-procs", CheckID: "deepintegrity",
		Severity:    audit.SeverityFail,
		Title:       fmt.Sprintf("Process count mismatch: ps=%s, /proc=%s (possible hidden processes)", psCount, procCount),
		Remediation: "Investigate with: diff <(ps -e --no-headers | awk '{print $1}' | sort) <(ls /proc | grep '^[0-9]' | sort)",
	}}
}

// checkHiddenPorts compares ss output with /proc/net/tcp.
func checkHiddenPorts(ctx context.Context, col collector.Collector) []audit.Finding {
	// Count from ss
	ssOut, err := col.Exec(ctx, "ss -tlnp 2>/dev/null | tail -n +2 | wc -l")
	if err != nil {
		return nil
	}
	// Count from /proc/net/tcp (exclude header + listening state 0A)
	procOut, err := col.Exec(ctx, "cat /proc/net/tcp /proc/net/tcp6 2>/dev/null | grep ' 0A ' | wc -l")
	if err != nil {
		return nil
	}

	ssCount := strings.TrimSpace(string(ssOut))
	procCount := strings.TrimSpace(string(procOut))

	if ssCount == procCount {
		return []audit.Finding{{
			ID: "deep-hidden-ports", CheckID: "deepintegrity",
			Severity: audit.SeverityPass,
			Title:    fmt.Sprintf("No hidden ports (ss=%s, /proc/net=%s)", ssCount, procCount),
		}}
	}

	return []audit.Finding{{
		ID: "deep-hidden-ports", CheckID: "deepintegrity",
		Severity: audit.SeverityWarn,
		Title:    fmt.Sprintf("Listening port count mismatch: ss=%s, /proc/net=%s", ssCount, procCount),
	}}
}

// checkOutboundConnections correlates each outbound connection with its process and package.
func checkOutboundConnections(ctx context.Context, col collector.Collector) []audit.Finding {
	out, err := col.Exec(ctx, "ss -tnp state established 2>/dev/null | tail -n +2")
	if err != nil {
		return nil
	}

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	var suspicious []string

	for _, line := range lines {
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}

		peer := fields[3]
		process := ""
		if len(fields) >= 5 {
			process = fields[4]
		}

		// Skip local connections
		if strings.HasPrefix(peer, "127.") || strings.HasPrefix(peer, "10.") || strings.HasPrefix(peer, "172.") || strings.HasPrefix(peer, "192.168.") {
			continue
		}

		// Extract process name
		procName := extractProcessName(process)

		// Known safe processes
		if isKnownOutbound(procName) {
			continue
		}

		if procName == "" {
			suspicious = append(suspicious, fmt.Sprintf("  %s → unknown process", peer))
		} else {
			suspicious = append(suspicious, fmt.Sprintf("  %s → %s", peer, procName))
		}
	}

	if len(suspicious) == 0 {
		return []audit.Finding{{
			ID: "deep-outbound", CheckID: "deepintegrity",
			Severity: audit.SeverityPass,
			Title:    "All outbound connections from known processes",
		}}
	}

	return []audit.Finding{{
		ID: "deep-outbound", CheckID: "deepintegrity",
		Severity: audit.SeverityInfo,
		Title:    fmt.Sprintf("Outbound connections to review (%d)", len(suspicious)),
		Evidence: strings.Join(suspicious, "\n"),
	}}
}

// Rootkit signatures: known files and directories
var rootkitPaths = []string{
	"/dev/.hax", "/dev/.usb", "/dev/.usbhid",
	"/etc/ld.so.hash", "/etc/rc.d/rsha",
	"/usr/bin/sourcemask", "/usr/bin/ras2xm",
	"/usr/sbin/in.telnet", "/usr/sbin/jcd",
	"/tmp/.scsi", "/tmp/.font-unix/.LCK",
	"/var/run/.tmp", "/var/tmp/.ICE-unix/.X11",
	"/dev/shm/.IPC", "/dev/shm/.X11",
	"/usr/include/file.h", "/usr/include/hosts.h",
	"/usr/lib/libext-2.so", "/usr/lib/libns2.so",
}

func checkRootkitSignatures(ctx context.Context, col collector.Collector) []audit.Finding {
	var found []string

	for _, path := range rootkitPaths {
		out, err := col.Exec(ctx, fmt.Sprintf("test -e %q && echo found 2>/dev/null", path))
		if err == nil && strings.Contains(string(out), "found") {
			found = append(found, path)
		}
	}

	if len(found) > 0 {
		return []audit.Finding{{
			ID: "deep-rootkit-signatures", CheckID: "deepintegrity",
			Severity:    audit.SeverityCritical,
			Title:       fmt.Sprintf("Rootkit signatures detected (%d)", len(found)),
			Evidence:    strings.Join(found, "\n"),
			Remediation: "CRITICAL: Potential rootkit detected. Isolate the server, investigate, and consider reinstalling the OS.",
		}}
	}

	return []audit.Finding{{
		ID: "deep-rootkit-signatures", CheckID: "deepintegrity",
		Severity: audit.SeverityPass,
		Title:    "No rootkit signatures detected",
	}}
}

func checkKernelModules(ctx context.Context, col collector.Collector) []audit.Finding {
	out, err := col.Exec(ctx, "lsmod 2>/dev/null")
	if err != nil {
		return nil
	}

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	suspiciousModules := []string{}

	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) < 1 {
			continue
		}
		mod := fields[0]

		// Check if module exists in the kernel tree using modinfo
		modOut, err := col.Exec(ctx, fmt.Sprintf("modinfo %s 2>/dev/null | grep -E '^filename:'", mod))
		if err != nil || strings.TrimSpace(string(modOut)) == "" {
			if !isKnownModule(mod) {
				suspiciousModules = append(suspiciousModules, mod)
			}
			continue
		}

		filename := strings.TrimSpace(string(modOut))
		// Out-of-tree modules typically not under /lib/modules/.../kernel/
		if !strings.Contains(filename, "/kernel/") && !strings.Contains(filename, "(builtin)") {
			if !isKnownModule(mod) {
				suspiciousModules = append(suspiciousModules, mod)
			}
		}
	}

	if len(suspiciousModules) > 0 {
		return []audit.Finding{{
			ID: "deep-kernel-modules", CheckID: "deepintegrity",
			Severity: audit.SeverityWarn,
			Title:    fmt.Sprintf("Out-of-tree kernel modules loaded (%d)", len(suspiciousModules)),
			Evidence: strings.Join(suspiciousModules, ", "),
		}}
	}

	return []audit.Finding{{
		ID: "deep-kernel-modules", CheckID: "deepintegrity",
		Severity: audit.SeverityPass,
		Title:    fmt.Sprintf("All %d kernel modules from standard tree", len(lines)-1),
	}}
}

func checkHiddenFiles(ctx context.Context, col collector.Collector) []audit.Finding {
	dirs := []string{"/etc", "/usr/bin", "/usr/sbin", "/var/log"}
	var found []string

	for _, dir := range dirs {
		out, err := col.Exec(ctx, fmt.Sprintf("find %s -maxdepth 1 -name '.*' -not -name '.' -not -name '..' -not -name '.gitkeep' -not -name '.placeholder' 2>/dev/null", dir))
		if err != nil || strings.TrimSpace(string(out)) == "" {
			continue
		}
		for _, f := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			if f != "" && !isKnownHiddenFile(f) {
				found = append(found, f)
			}
		}
	}

	if len(found) > 0 {
		return []audit.Finding{{
			ID: "deep-hidden-files", CheckID: "deepintegrity",
			Severity: audit.SeverityWarn,
			Title:    fmt.Sprintf("Hidden files in system directories (%d)", len(found)),
			Evidence: strings.Join(found, "\n"),
		}}
	}

	return []audit.Finding{{
		ID: "deep-hidden-files", CheckID: "deepintegrity",
		Severity: audit.SeverityPass,
		Title:    "No unexpected hidden files in system directories",
	}}
}

func checkRkhunterWrapper(ctx context.Context, col collector.Collector) []audit.Finding {
	// If rkhunter is installed, run it and parse results
	out, err := col.Exec(ctx, "which rkhunter 2>/dev/null")
	if err != nil || strings.TrimSpace(string(out)) == "" {
		return nil
	}

	out, err = col.Exec(ctx, "rkhunter --check --skip-keypress --report-warnings-only 2>/dev/null | head -30")
	if err != nil {
		return nil
	}

	warnings := strings.TrimSpace(string(out))
	if warnings == "" {
		return []audit.Finding{{
			ID: "deep-rkhunter", CheckID: "deepintegrity",
			Severity: audit.SeverityPass,
			Title:    "rkhunter: no warnings",
		}}
	}

	lines := strings.Split(warnings, "\n")
	return []audit.Finding{{
		ID: "deep-rkhunter", CheckID: "deepintegrity",
		Severity: audit.SeverityWarn,
		Title:    fmt.Sprintf("rkhunter: %d warnings", len(lines)),
		Evidence: warnings,
	}}
}

func extractProcessName(field string) string {
	// ss format: users:(("processname",pid=1234,fd=5))
	if idx := strings.Index(field, "((\""); idx >= 0 {
		end := strings.Index(field[idx+3:], "\"")
		if end > 0 {
			return field[idx+3 : idx+3+end]
		}
	}
	return ""
}

func isKnownOrphan(path string) bool {
	known := map[string]bool{
		"/usr/local/bin/k3s":         true,
		"/usr/local/bin/step":        true,
		"/usr/local/bin/step-ca":     true,
		"/usr/bin/gh":                true,
		"/usr/local/bin/docker":      true,
		"/usr/local/bin/containerd":  true,
		"/usr/local/bin/helm":        true,
		"/usr/local/bin/kubectl":     true,
		"/usr/local/bin/node":        true,
		"/usr/local/bin/go":          true,
		"/usr/local/bin/golangci-lint": true,
	}
	return known[path]
}

func isKnownOutbound(proc string) bool {
	known := map[string]bool{
		"sshd": true, "ssh": true, "apt": true, "apt-get": true,
		"dpkg": true, "curl": true, "wget": true, "git": true,
		"containerd": true, "dockerd": true, "k3s": true,
		"node": true, "step-ca": true, "chronyd": true,
		"systemd-timesyncd": true, "ntpd": true,
	}
	return known[proc]
}

func isKnownModule(mod string) bool {
	known := map[string]bool{
		"wireguard": true, "vboxdrv": true, "vboxnetflt": true,
		"nvidia": true, "nvidia_drm": true, "nvidia_modeset": true,
	}
	return known[mod]
}

func isKnownHiddenFile(path string) bool {
	known := map[string]bool{
		"/etc/.pwd.lock":       true,
		"/etc/.updated":        true,
		"/etc/.java":           true,
		"/var/log/.rkhunter":   true,
	}
	return known[path]
}
