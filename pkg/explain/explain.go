// Package explain provides human-readable descriptions for audit findings.
// Used by the --explain flag to make reports accessible to non-experts.
package explain

import "github.com/Siovos/siovos-audit/pkg/audit"

// Explanation provides context for a finding.
type Explanation struct {
	Why  string // Why this matters
	Risk string // What could happen if not fixed
	Fix  string // Concrete steps to fix (OS-aware)
}

// Enrich adds explanations to findings that have them.
func Enrich(findings []audit.Finding) []audit.Finding {
	for i := range findings {
		if findings[i].Severity <= audit.SeverityInfo {
			continue
		}
		if exp, ok := catalog[findings[i].ID]; ok {
			if findings[i].Description == "" {
				findings[i].Description = exp.Why
			}
			if findings[i].Remediation == "" || len(exp.Fix) > len(findings[i].Remediation) {
				findings[i].Remediation = exp.Fix
			}
		} else if exp, ok := prefixMatch(findings[i].ID); ok {
			if findings[i].Description == "" {
				findings[i].Description = exp.Why
			}
		}
	}
	return findings
}

func prefixMatch(id string) (Explanation, bool) {
	for prefix, exp := range prefixCatalog {
		if len(id) >= len(prefix) && id[:len(prefix)] == prefix {
			return exp, true
		}
	}
	return Explanation{}, false
}

var prefixCatalog = map[string]Explanation{
	"firewall-open-port": {
		Why: "An open port means a service is accepting connections from the internet. If the service has a vulnerability or weak credentials, an attacker can exploit it.",
	},
	"services-exposed": {
		Why: "A publicly exposed service increases your attack surface. Services should only be accessible to those who need them.",
	},
	"cron-perms-": {
		Why: "If cron directories are world-writable or too open, any user could add scheduled tasks running as root.",
	},
	"secrets-env-": {
		Why: "Environment files often contain database passwords, API keys, and other credentials. If accessible via web server, anyone can read them.",
	},
	"secrets-git-": {
		Why: "A .git directory exposes source code, commit history, and potentially credentials.",
	},
	"postexploit-tmp-exec": {
		Why: "Executables in /tmp or /dev/shm are a common indicator of compromise. Attackers download and run malware in world-writable directories.",
	},
	"container-dangerous-volume": {
		Why: "Mounting the host root filesystem, /etc, or the Docker socket into a container gives the container full host access.",
	},
}

var catalog = map[string]Explanation{
	// SSH
	"ssh-password-auth": {
		Why:  "Password authentication allows brute-force attacks. Attackers can try thousands of passwords per minute against your SSH server.",
		Risk: "An attacker could gain full access to your server by guessing or brute-forcing a password.",
		Fix:  "1. Ensure you have SSH key access configured\n2. Edit /etc/ssh/sshd_config: set PasswordAuthentication no\n3. Restart SSH: systemctl restart sshd",
	},
	"ssh-root-login": {
		Why:  "Allowing root login via SSH means an attacker only needs one credential to get full control. Using a regular user + sudo adds a layer of defense.",
		Risk: "Direct root compromise — the attacker gets maximum privileges immediately.",
		Fix:  "1. Edit /etc/ssh/sshd_config: set PermitRootLogin prohibit-password (or no)\n2. Restart SSH: systemctl restart sshd",
	},
	"ssh-empty-passwords": {
		Why:  "Accounts with empty passwords can be accessed by anyone without any credential.",
		Risk: "Instant unauthorized access to the server.",
		Fix:  "1. Edit /etc/ssh/sshd_config: set PermitEmptyPasswords no\n2. Restart SSH: systemctl restart sshd",
	},
	"ssh-max-auth-tries": {
		Why:  "A high MaxAuthTries value gives attackers more attempts per connection to guess credentials.",
		Risk: "Easier brute-force attacks against SSH.",
		Fix:  "Edit /etc/ssh/sshd_config: set MaxAuthTries 3",
	},
	"ssh-x11-forwarding": {
		Why:  "X11 forwarding allows graphical applications to be forwarded over SSH. On a server, this is unnecessary and increases attack surface.",
		Risk: "An attacker with SSH access could exploit X11 vulnerabilities.",
		Fix:  "Edit /etc/ssh/sshd_config: set X11Forwarding no",
	},
	"ssh-client-alive": {
		Why:  "Without a timeout, idle SSH sessions stay open indefinitely. An unattended terminal could be used by someone with physical access.",
		Risk: "Abandoned SSH sessions could be hijacked.",
		Fix:  "Edit /etc/ssh/sshd_config:\n  ClientAliveInterval 300\n  ClientAliveCountMax 3",
	},
	"ssh-ciphers": {
		Why:  "Weak ciphers (3DES, CBC mode) have known vulnerabilities. Modern ciphers like ChaCha20 and AES-GCM are faster and more secure.",
		Risk: "Encrypted SSH traffic could potentially be decrypted by an advanced attacker.",
		Fix:  "Edit /etc/ssh/sshd_config:\n  Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com",
	},
	"ssh-macs": {
		Why:  "Weak MACs (MD5-based) can be forged more easily, compromising the integrity of the SSH connection.",
		Risk: "An attacker could modify data in transit without detection.",
		Fix:  "Edit /etc/ssh/sshd_config:\n  MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com",
	},
	"ssh-kex": {
		Why:  "Weak key exchange algorithms (SHA1-based) are vulnerable to collision attacks.",
		Risk: "The initial key exchange could be compromised, allowing decryption of the entire session.",
		Fix:  "Edit /etc/ssh/sshd_config:\n  KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org",
	},
	"ssh-strict-modes": {
		Why:  "StrictModes checks file permissions on SSH config files. Without it, a misconfigured file could allow unauthorized access.",
		Risk: "An attacker could modify authorized_keys with bad permissions.",
		Fix:  "Edit /etc/ssh/sshd_config: set StrictModes yes",
	},
	"ssh-config-perms": {
		Why:  "If sshd_config is writable by non-root users, an attacker could modify SSH settings to allow unauthorized access.",
		Risk: "Complete SSH configuration takeover.",
		Fix:  "chmod 600 /etc/ssh/sshd_config",
	},

	// Firewall
	"firewall-active": {
		Why:  "A firewall is your first line of defense. Without it, every service on your server is directly accessible from the internet.",
		Risk: "All services are exposed — databases, admin panels, debug ports.",
		Fix:  "apt install ufw && ufw default deny incoming && ufw allow ssh && ufw enable",
	},
	"firewall-default-deny": {
		Why:  "Default deny means only explicitly allowed traffic gets through. Without it, any new service you start is automatically exposed.",
		Risk: "Accidentally exposed services.",
		Fix:  "ufw default deny incoming",
	},
	"firewall-fail2ban": {
		Why:  "fail2ban automatically bans IPs that show malicious signs (failed logins, probing). It's an active defense layer.",
		Risk: "Brute-force attacks can continue indefinitely without being blocked.",
		Fix:  "apt install fail2ban && systemctl enable --now fail2ban",
	},
	"firewall-logging": {
		Why:  "Firewall logging records blocked and allowed connections. Essential for detecting attacks and debugging connectivity issues.",
		Risk: "You won't know if someone is probing your server.",
		Fix:  "ufw logging on",
	},

	// Auth
	"auth-multiple-uid0": {
		Why:  "Only root should have UID 0. Multiple accounts with UID 0 means multiple ways to get full system control.",
		Risk: "Hidden root-equivalent accounts that bypass monitoring.",
		Fix:  "Check /etc/passwd for accounts with UID 0 and change their UID or remove them.",
	},
	"auth-passwordless": {
		Why:  "Accounts without passwords can be accessed without any credential if the service allows it.",
		Risk: "Unauthorized access to the system.",
		Fix:  "Lock the accounts: passwd -l <username>",
	},
	"auth-sudo-nopasswd": {
		Why:  "NOPASSWD sudo means anyone who compromises that user account gets instant root access without knowing a password.",
		Risk: "Privilege escalation from a compromised user to root.",
		Fix:  "Review /etc/sudoers and /etc/sudoers.d/. Remove NOPASSWD unless strictly required.",
	},

	// Logging
	"logging-syslog": {
		Why:  "Without a syslog daemon, system events are not recorded. You won't know what happened during or after an incident.",
		Risk: "No audit trail. Attacks go undetected.",
		Fix:  "apt install rsyslog && systemctl enable --now rsyslog",
	},
	"logging-auditd": {
		Why:  "auditd provides detailed kernel-level auditing — who accessed what file, who ran what command. Essential for compliance and forensics.",
		Risk: "No detailed audit trail for security investigations.",
		Fix:  "apt install auditd && systemctl enable --now auditd",
	},
	"logging-logrotate": {
		Why:  "Without log rotation, logs grow indefinitely until they fill the disk, potentially crashing the server.",
		Risk: "Disk full, service outage.",
		Fix:  "apt install logrotate",
	},

	// System
	"system-updates": {
		Why:  "Security updates patch known vulnerabilities. Unpatched systems are easy targets.",
		Risk: "Known exploits can be used against your server.",
		Fix:  "apt update && apt upgrade",
	},
	"system-mac": {
		Why:  "Mandatory Access Control (AppArmor/SELinux) confines programs to limited resources. Even if a service is compromised, the damage is contained.",
		Risk: "A compromised service gets full access to the system.",
		Fix:  "apt install apparmor apparmor-utils && systemctl enable --now apparmor",
	},

	// Database
	"db-mysql-bind": {
		Why:  "A database listening on all interfaces is accessible from the internet. Databases should only be reachable from localhost or trusted networks.",
		Risk: "Direct database access from the internet — data theft, deletion, ransomware.",
		Fix:  "Edit MySQL config: set bind-address = 127.0.0.1 and restart MySQL.",
	},
	"db-redis-auth": {
		Why:  "Redis without a password is accessible to anyone who can reach the port. Redis commands can write files to disk, enabling remote code execution.",
		Risk: "Complete server compromise via Redis (writing SSH keys, crontabs).",
		Fix:  "Set requirepass in /etc/redis/redis.conf and restart Redis.",
	},
	"db-pg-trust": {
		Why:  "Trust authentication in PostgreSQL means any connection from the matching source is accepted without a password.",
		Risk: "Unauthorized database access.",
		Fix:  "Replace 'trust' with 'scram-sha-256' in pg_hba.conf and restart PostgreSQL.",
	},

	// Web
	"web-nginx-tokens": {
		Why:  "Server version disclosure tells attackers exactly what software and version you run, making it easier to find matching exploits.",
		Risk: "Targeted attacks using known vulnerabilities for your exact version.",
		Fix:  "Add 'server_tokens off;' in nginx.conf http block.",
	},
	"web-nginx-headers": {
		Why:  "Security headers protect against common web attacks: clickjacking (X-Frame-Options), MIME sniffing (X-Content-Type), XSS (CSP).",
		Risk: "Web application attacks against services behind Nginx.",
		Fix:  "Add to nginx server blocks:\n  add_header X-Frame-Options SAMEORIGIN;\n  add_header X-Content-Type-Options nosniff;",
	},

	// Time
	"time-ntp-daemon": {
		Why:  "Accurate time is critical for log correlation, TLS certificate validation, and Kerberos authentication. Clock drift breaks all of these.",
		Risk: "Invalid TLS certificates, broken authentication, inaccurate logs.",
		Fix:  "timedatectl set-ntp true",
	},

	// Malware
	"malware-none": {
		Why:  "Anti-malware tools detect rootkits, backdoors, and known malicious patterns. Without them, a compromise might go undetected.",
		Risk: "Persistent compromise without detection.",
		Fix:  "apt install chkrootkit rkhunter",
	},

	// Integrity
	"integrity-none": {
		Why:  "File integrity monitoring detects unauthorized changes to system files. If an attacker modifies binaries or configs, you'll know.",
		Risk: "Tampered system files go undetected.",
		Fix:  "Install AIDE: apt install aide && aideinit",
	},

	// Cron
	"cron-perms-crontab": {
		Why:  "If cron directories are world-writable or too open, any user could add scheduled tasks running as root.",
		Risk: "Privilege escalation via cron job injection.",
		Fix:  "chmod 600 /etc/crontab && chmod 700 /etc/cron.d /etc/cron.daily /etc/cron.hourly",
	},

	// Shells
	"shells-tmout": {
		Why:  "Without an idle timeout, SSH sessions stay open indefinitely. An unattended terminal is a security risk.",
		Risk: "Abandoned sessions can be hijacked by someone with physical or network access.",
		Fix:  "Add to /etc/profile.d/timeout.sh:\n  TMOUT=900\n  readonly TMOUT\n  export TMOUT",
	},

	// Secrets
	"secrets-git-": {
		Why:  "A .git directory in a webroot exposes your entire source code, commit history, and potentially credentials to anyone on the internet.",
		Risk: "Source code leak, credential exposure, full application compromise.",
		Fix:  "Remove .git from webroot or add to nginx: location ~ /\\.git { deny all; }",
	},

	// Post-exploit
	"postexploit-modified-binaries": {
		Why:  "System binaries modified outside the package manager could indicate a rootkit or backdoor installation.",
		Risk: "Persistent backdoor allowing the attacker to return even after password changes.",
		Fix:  "Verify the files: dpkg -V or rpm -Va. Reinstall affected packages. Investigate the cause.",
	},

	// Container
	"container-privileged": {
		Why:  "Privileged containers have full access to the host kernel. A container escape gives root on the host.",
		Risk: "Complete host compromise from within a container.",
		Fix:  "Remove --privileged flag. Use specific capabilities (--cap-add) instead.",
	},
	"container-socket-perms": {
		Why:  "The Docker socket grants root-equivalent access. If world-readable, any user can control Docker and the host.",
		Risk: "Any local user can become root via Docker.",
		Fix:  "chmod 660 /var/run/docker.sock && chgrp docker /var/run/docker.sock",
	},

	// Backup
	"backup-none": {
		Why:  "Without backups, a ransomware attack, hardware failure, or accidental deletion means permanent data loss.",
		Risk: "Irrecoverable data loss.",
		Fix:  "Install a backup tool (restic, borg) and configure automated daily backups to an off-site location.",
	},

	// DNS
	"dns-spf": {
		Why:  "Without SPF, anyone can send emails pretending to be from your domain. Email spoofing is used in phishing attacks.",
		Risk: "Your domain used in phishing campaigns, reputation damage.",
		Fix:  "Add a DNS TXT record: v=spf1 mx -all (adjust for your mail setup)",
	},
	"dns-dmarc": {
		Why:  "DMARC tells receiving mail servers what to do with emails that fail SPF/DKIM. Without it, spoofed emails may still be delivered.",
		Risk: "Phishing emails from your domain reach inboxes.",
		Fix:  "Add a DNS TXT record at _dmarc.yourdomain.com: v=DMARC1; p=reject;",
	},

	// Database
	"db-pg-listen": {
		Why:  "A database listening on all interfaces is accessible from the internet, bypassing application-level security.",
		Risk: "Direct database access — data theft, modification, or deletion.",
		Fix:  "Set listen_addresses = 'localhost' in postgresql.conf and restart PostgreSQL.",
	},
	"db-mongo-auth": {
		Why:  "MongoDB without authorization allows anyone to read, write, and delete all data without credentials.",
		Risk: "Complete data compromise. MongoDB ransomware attacks are common.",
		Fix:  "Enable authorization in /etc/mongod.conf: security.authorization: enabled",
	},

	// Webserver
	"web-nginx-ssl": {
		Why:  "TLS 1.0 and 1.1 have known vulnerabilities (POODLE, BEAST). Modern browsers don't even support them.",
		Risk: "Encrypted traffic could be decrypted by an attacker.",
		Fix:  "Set in nginx: ssl_protocols TLSv1.2 TLSv1.3;",
	},
	"web-nginx-access-log": {
		Why:  "Without access logs, you can't detect attacks, debug issues, or analyze traffic patterns.",
		Risk: "Attacks go undetected, no forensic evidence.",
		Fix:  "Ensure access_log is enabled in nginx server blocks.",
	},

	// System
	"system-core-dumps": {
		Why:  "Core dumps of SUID programs can contain sensitive data like passwords and encryption keys.",
		Risk: "Credential leakage from core dump files.",
		Fix:  "Set fs.suid_dumpable = 0 in /etc/sysctl.conf && sysctl -p",
	},
	"system-tmp-noexec": {
		Why:  "/tmp without noexec allows attackers to download and execute malware in a world-writable directory.",
		Risk: "Easy malware execution after initial compromise.",
		Fix:  "Add noexec to /tmp mount options in /etc/fstab",
	},
	"system-umask": {
		Why:  "A permissive umask means newly created files are readable by other users by default.",
		Risk: "Accidental exposure of sensitive files.",
		Fix:  "Set UMASK 027 in /etc/login.defs",
	},

	// Packages
	"pkg-gpg": {
		Why:  "Repositories without GPG verification can serve tampered packages. A compromised mirror could install backdoors.",
		Risk: "Supply chain attack via malicious package updates.",
		Fix:  "Remove 'trusted=yes' from APT sources or set gpgcheck=1 in YUM repos.",
	},
}
