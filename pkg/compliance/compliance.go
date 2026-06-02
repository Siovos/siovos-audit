// Package compliance maps audit findings to compliance frameworks.
package compliance

// Framework represents a compliance standard.
type Framework struct {
	ID          string
	Name        string
	Description string
	Controls    []Control
}

// Control maps a compliance requirement to finding IDs.
type Control struct {
	ID          string   // e.g. "CC6.1" for SOC2
	Name        string
	Description string
	FindingIDs  []string // Finding IDs that satisfy this control
}

// Frameworks contains all available compliance templates.
var Frameworks = map[string]Framework{
	"cis-level1": {
		ID:          "cis-level1",
		Name:        "CIS Benchmark Level 1",
		Description: "Center for Internet Security Benchmark — essential security controls",
		Controls: []Control{
			{ID: "1.5.1", Name: "Core dumps restricted", FindingIDs: []string{"system-core-dumps"}},
			{ID: "1.5.2", Name: "ASLR enabled", FindingIDs: []string{"system-sysctl-kernel-randomize_va_space"}},
			{ID: "1.6", Name: "MAC framework", FindingIDs: []string{"system-mac"}},
			{ID: "2.1.1", Name: "No telnet server", FindingIDs: []string{"insecure-telnetd"}},
			{ID: "2.2.1", Name: "Time synchronization", FindingIDs: []string{"time-ntp-daemon", "time-synced"}},
			{ID: "3.3.1", Name: "Source routed packets", FindingIDs: []string{"system-sysctl-net-ipv4-conf-all-send_redirects"}},
			{ID: "3.3.2", Name: "ICMP redirects", FindingIDs: []string{"system-sysctl-net-ipv4-conf-all-accept_redirects"}},
			{ID: "3.3.7", Name: "Reverse path filtering", FindingIDs: []string{"system-sysctl-net-ipv4-conf-all-rp_filter"}},
			{ID: "3.3.8", Name: "TCP SYN cookies", FindingIDs: []string{"network-syn-cookies"}},
			{ID: "4.1.1", Name: "Audit daemon", FindingIDs: []string{"logging-auditd"}},
			{ID: "4.2.1", Name: "Syslog configured", FindingIDs: []string{"logging-syslog"}},
			{ID: "5.1", Name: "Cron permissions", FindingIDs: []string{"cron-perms-crontab", "cron-perms-cron-d", "cron-perms-cron-daily"}},
			{ID: "5.2.1", Name: "SSH protocol", FindingIDs: []string{"ssh-protocol"}},
			{ID: "5.2.5", Name: "SSH MaxAuthTries", FindingIDs: []string{"ssh-max-auth-tries"}},
			{ID: "5.2.6", Name: "SSH X11 forwarding", FindingIDs: []string{"ssh-x11-forwarding"}},
			{ID: "5.2.8", Name: "SSH root login", FindingIDs: []string{"ssh-root-login"}},
			{ID: "5.2.10", Name: "SSH password auth", FindingIDs: []string{"ssh-password-auth"}},
			{ID: "5.2.11", Name: "SSH empty passwords", FindingIDs: []string{"ssh-empty-passwords"}},
			{ID: "5.2.13", Name: "SSH client alive", FindingIDs: []string{"ssh-client-alive"}},
			{ID: "5.4.4", Name: "Password hashing", FindingIDs: []string{"auth-password-hashing"}},
			{ID: "5.5.2", Name: "System accounts", FindingIDs: []string{"auth-system-shells"}},
			{ID: "5.5.4", Name: "Session timeout", FindingIDs: []string{"shells-tmout"}},
			{ID: "5.5.5", Name: "Default umask", FindingIDs: []string{"system-umask"}},
			{ID: "6.1", Name: "File permissions", FindingIDs: []string{"system-perms-etc-shadow", "system-perms-etc-passwd"}},
			{ID: "6.2.1", Name: "No passwordless accounts", FindingIDs: []string{"auth-passwordless"}},
			{ID: "6.2.2", Name: "Single UID 0", FindingIDs: []string{"auth-multiple-uid0"}},
			{ID: "6.2.6", Name: "Home permissions", FindingIDs: []string{"shells-home-root"}},
		},
	},
	"soc2-basic": {
		ID:          "soc2-basic",
		Name:        "SOC 2 Type II (Basic)",
		Description: "Service Organization Control 2 — basic security controls mapping",
		Controls: []Control{
			{ID: "CC6.1", Name: "Access control", Description: "Logical and physical access controls", FindingIDs: []string{"ssh-password-auth", "ssh-root-login", "auth-multiple-uid0", "auth-passwordless", "auth-sudo-nopasswd", "firewall-active", "firewall-default-deny"}},
			{ID: "CC6.2", Name: "System credentials", Description: "Credentials management", FindingIDs: []string{"ssh-password-auth", "ssh-empty-passwords", "auth-password-hashing", "db-redis-auth", "db-pg-trust"}},
			{ID: "CC6.3", Name: "Encryption", Description: "Encryption of data", FindingIDs: []string{"ssh-ciphers", "ssh-macs", "ssh-kex"}},
			{ID: "CC6.6", Name: "Network security", Description: "Network boundary protection", FindingIDs: []string{"firewall-active", "firewall-default-deny", "firewall-logging"}},
			{ID: "CC6.8", Name: "Malware prevention", Description: "Detection and prevention of malware", FindingIDs: []string{"malware-none", "malware-chkrootkit", "malware-rkhunter", "malware-ClamAV"}},
			{ID: "CC7.1", Name: "Monitoring", Description: "Detection of anomalies", FindingIDs: []string{"logging-syslog", "logging-auditd", "integrity-none"}},
			{ID: "CC7.2", Name: "Incident response", Description: "Monitoring and response", FindingIDs: []string{"logging-syslog", "logging-auth-log", "auth-failed-logins"}},
			{ID: "CC8.1", Name: "Change management", Description: "System changes are controlled", FindingIDs: []string{"system-updates", "system-mac"}},
		},
	},
}

// FrameworkList returns all available frameworks.
func FrameworkList() []Framework {
	return []Framework{
		Frameworks["cis-level1"],
		Frameworks["soc2-basic"],
	}
}
