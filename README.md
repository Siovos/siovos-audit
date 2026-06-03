# Siovos Audit

Open source server security audit tool. Score your infrastructure security in seconds.

Single binary, agentless, connects via SSH. Nothing to install on the target.

## Quick start

```bash
# Install (Linux, macOS)
curl -fsSL https://raw.githubusercontent.com/Siovos/siovos-audit/main/install.sh | sh

# Or via Go
go install github.com/Siovos/siovos-audit@latest

# Audit a remote server
siovos-audit run --host 192.168.1.100 --user root

# Interactive mode (guided prompts)
siovos-audit run

# With a server profile
siovos-audit run --host 192.168.1.100 --user root --profile kubernetes-node

# With detailed explanations
siovos-audit run --host 192.168.1.100 --user root --explain

# CIS compliance report
siovos-audit run --host 192.168.1.100 --user root --compliance cis-level1

# Audit the local machine
siovos-audit run --local

# JSON output (for CI/CD)
siovos-audit run --host 192.168.1.100 --user root --format json --min-score 80

# HTML report
siovos-audit run --host 192.168.1.100 --user root --format html > report.html

# Compare two servers
siovos-audit compare --host1 server-a.com --host2 server-b.com --user root

# Server inventory (what's running, no scoring)
siovos-audit inventory --host 192.168.1.100 --user root

# View audit history
siovos-audit history

# Update to latest version
siovos-audit update
```

## Example output

```
  Siovos Audit
  Target: my-server.com (Debian GNU/Linux 13)

  auth .................................... 95/100
    [PASS] Only root has UID 0
    [PASS] Strong password hashing: YESCRYPT
    [WARN] NOPASSWD sudo rules found (1)

  firewall ................................ 100/100
    [PASS] UFW active
    [PASS] Default deny incoming
    [PASS] Port 6443 (Kubernetes API) listening but blocked by firewall
    [PASS] Firewall logging enabled

  kubernetes .............................. 95/100
    [PASS] RBAC enabled
    [PASS] Network policies defined (5)
    [PASS] API server not exposed on all interfaces

  ssh ..................................... 90/100
    [PASS] Password authentication disabled
    [INFO] Root login via key only
    [PASS] StrictModes enabled
    [WARN] MaxAuthTries at default (6)

  system .................................. 95/100
    [PASS] No pending security updates
    [PASS] AppArmor enabled
    [PASS] ASLR enabled
    [PASS] Core dumps disabled for SUID binaries

  Overall Score: 95/100
  0 issues to fix, 3 warnings to review
```

## Security checks (26 categories)

### Core hardening
| Check | What it verifies |
|---|---|
| **SSH** (19 checks) | Password auth, root login, ciphers, MACs, KexAlgorithms, X11/TCP forwarding, MaxAuthTries, ClientAlive, permissions |
| **Firewall** (7) | UFW/iptables, default deny, open ports cross-referenced with UFW rules, fail2ban, logging |
| **TLS** (5) | Certificate validity, expiration, signature algorithm, key size (RSA vs ECDSA) |
| **System** (14) | Updates, unattended-upgrades, file permissions, kernel hardening (sysctl), ASLR, core dumps, mount options, umask, AppArmor/SELinux |
| **Network** (6) | DNS, IPv6, listening services, IP forwarding, SYN cookies, promiscuous interfaces |
| **Auth** (7) | UID 0 duplicates, passwordless accounts, system shells, password hashing/aging, sudo NOPASSWD, failed logins |

### Services & applications
| Check | What it verifies |
|---|---|
| **Services** (4) | Publicly exposed services with port identification, cross-referenced with firewall |
| **Database** (4) | MySQL bind/permissions, PostgreSQL listen/trust auth, Redis requirepass/bind, MongoDB authorization |
| **Web Server** (5) | Nginx tokens/logging/headers/SSL, Apache ServerTokens/TraceEnable |
| **Kubernetes** (6) | RBAC, network policies, secrets encryption, API server, pods as root, K3s detection |
| **VPN** (3) | WireGuard interfaces, config permissions, peer handshakes |

### Infrastructure
| Check | What it verifies |
|---|---|
| **Logging** (5) | Syslog, auditd, logrotate, auth logs, remote logging |
| **Cron** (5) | Daemon, permissions, root/user jobs, at jobs, systemd timers |
| **Packages** (4) | GPG signing, security repos, kernel count, audit tools |
| **Insecure** (10) | Telnet, rsh, NIS, TFTP, FTP, inetd/xinetd detection |
| **Time** (2) | NTP daemon, clock synchronization |
| **Shells** (3) | TMOUT idle timeout, umask profiles, home permissions |
| **Storage** (2) | NFS exports, USB storage module |

### Advanced detection
| Check | What it verifies |
|---|---|
| **Secrets** (4) | .env files in webroots, .git exposed, config passwords, SSH key permissions |
| **Post-Exploit** (4) | Executables in /tmp, recent users, suspicious history, modified binaries |
| **DNS** (2) | SPF and DMARC records |
| **Containers** (3) | Docker socket, privileged containers, dangerous volumes |
| **Backups** (3) | Backup tools, cron jobs, systemd timers |
| **Malware** (1) | chkrootkit, rkhunter, ClamAV detection |
| **Integrity** (1) | AIDE, Tripwire, OSSEC, Wazuh, osquery detection |

### Deep integrity (intrusion detection)
| Check | What it verifies |
|---|---|
| **Deep Integrity** (9) | Orphan binaries (cross-refs processes with dpkg), package integrity (dpkg -V), hidden processes (ps vs /proc), hidden ports (ss vs /proc/net), outbound connections correlated with processes, rootkit signatures (20+ known paths), kernel modules verification, hidden files in system dirs, rkhunter wrapper |

## Features

- **Agentless** — connects via SSH, reads config, leaves. Nothing installed on your server.
- **Single binary** — download and run. No runtime, no dependencies.
- **130+ checks** across 27 categories.
- **Intelligent** — cross-references firewall rules with listening ports, adapts fail2ban severity when password auth is disabled.
- **Profiles** — `minimal-vps`, `web-server`, `kubernetes-node`, `database-server`, `vpn-gateway` with expected ports.
- **Interactive mode** — guided prompts when no flags are provided.
- **--explain** — human-readable descriptions of why each finding matters and how to fix it.
- **Compliance** — CIS Benchmark Level 1 and SOC2 Type II mappings.
- **Inventory** — `siovos-audit inventory` lists everything running on a server without scoring.
- **CI/CD ready** — JSON output, `--min-score` exit code, GitHub Action, GitLab CI template.
- **Compare** — side-by-side comparison of two servers.
- **History** — save and review past audit results.
- **Self-update** — `siovos-audit update` downloads the latest version.

## Server profiles

Profiles pre-configure expected ports and relevant checks:

```bash
# Basic VPS — SSH, web, standard checks
siovos-audit run --host x --user root --profile minimal-vps

# Kubernetes node — K8s ports expected, K8s checks enabled
siovos-audit run --host x --user root --profile kubernetes-node

# Add custom expected ports on top
siovos-audit run --host x --user root --profile kubernetes-node --expect-ports 9100,3000
```

Or in `.siovos-audit.yml`:

```yaml
profile: kubernetes-node
expected_ports: [9100, 9090]
suppress:
  - system-sysctl-net-ipv4-conf-all-rp_filter
```

## Build from source

```bash
git clone https://github.com/Siovos/siovos-audit.git
cd siovos-audit
make build
./bin/siovos-audit version
```

Requires Go 1.22+.

## Project structure

```
siovos-audit/
├── cmd/siovos-audit/     # CLI (run, compare, inventory, history, update)
├── pkg/
│   ├── audit/            # Engine, Check, Finding, Registry, Scorer, Facts, Config, Profiles
│   ├── collector/        # Transport: SSH, local, cached wrapper
│   ├── scoring/          # Score calculation
│   ├── reporter/         # Output: terminal, JSON, HTML
│   ├── explain/          # Pedagogical descriptions for findings
│   ├── compliance/       # CIS, SOC2 mappings
│   ├── store/            # Result persistence
│   └── plugin/           # External check plugin system
└── internal/checks/      # 26 check implementations
```

## Security guarantees

- **Read-only** — never modifies anything on the target
- **No credentials stored** — SSH keys are used in-memory only
- **No phone home** — all processing is local, no external calls
- **Minimal dependencies** — small attack surface

## Roadmap

- [x] 26 security check categories (~120 checks)
- [x] Intelligent cross-referencing (firewall rules, package manager, service detection)
- [x] Server profiles and expected ports
- [x] Interactive mode with guided prompts
- [x] --explain mode with pedagogical descriptions
- [x] CIS and SOC2 compliance templates
- [x] Server inventory command
- [x] CI/CD integration (GitHub Action + GitLab CI template)
- [x] Server comparison and audit history
- [x] Self-update command
- [ ] Web dashboard

## Contributing

Contributions welcome, especially new security checks. See `CONTRIBUTING.md` and the `Check` interface in `pkg/audit/check.go`.

## License

MIT — See [LICENSE](LICENSE) for details.
