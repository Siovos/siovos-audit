# Siovos Audit

Open source server security audit tool. Score your infrastructure security in seconds.

Single binary, agentless, connects via SSH. Nothing to install on the target.

## Quick start

```bash
# Install via Go
go install github.com/Siovos/siovos-audit@latest

# Audit a remote server
siovos-audit run --host 192.168.1.100 --user root

# Audit specific checks only
siovos-audit run --host 192.168.1.100 --user root --checks ssh,firewall

# Audit the local machine
siovos-audit run --local

# JSON output (for CI/CD)
siovos-audit run --host 192.168.1.100 --user root --format json

# Fail if score is below threshold
siovos-audit run --host 192.168.1.100 --user root --min-score 80
```

## Example output

```
  Siovos Audit
  Target: my-server.com (Debian 13)

  Firewall ....................................... 90/100
    [PASS] UFW active
    [PASS] Default deny incoming
    [WARN] Port 8080 open - verify if intentional

  SSH Security ................................... 85/100
    [PASS] Password authentication disabled
    [PASS] Root login via key only
    [PASS] Empty passwords not permitted
    [PASS] SSH Protocol 2

  TLS Certificates ............................... 95/100
    [PASS] Certificate valid: /etc/letsencrypt/live/example.com/fullchain.pem
    [WARN] Certificate expires within 30 days

  Exposed Services ............................... 70/100
    [FAIL] Redis accessible on public interface (port 6379)
    [WARN] Service exposed on port 3000
    [PASS] No unexpected services exposed

  Overall Score: 85/100
  1 issues to fix, 3 warnings to review
```

## Security checks

| Check | What it verifies |
|---|---|
| **SSH** | Password auth, root login, empty passwords, protocol version |
| **Firewall** | UFW/iptables active, default deny policy, unexpected open ports |
| **TLS** | Certificate validity, expiration, signature algorithm, key size |
| **Services** | Publicly exposed services, high-risk ports (databases, Docker API) |

## Why this tool

Most developers deploy on a VPS, follow a hardening tutorial, and never verify the result. Existing tools are either enterprise-grade (OpenSCAP), require installation on the target (Lynis), or need a Ruby runtime (InSpec).

Siovos Audit is different:
- **Agentless** - connects via SSH, reads config, leaves. Nothing installed on your server.
- **Single binary** - download and run. No runtime, no dependencies.
- **Opinionated** - useful checks out of the box, no profiles to write.
- **Scoring** - clear 0-100 score per category with PASS/WARN/FAIL for each finding.
- **CI/CD ready** - JSON output and `--min-score` flag for pipeline gates.

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
├── cmd/siovos-audit/     # CLI entry point
├── pkg/
│   ├── audit/            # Core types: Engine, Check, Finding, Registry, Scorer
│   ├── collector/        # Transport abstraction: SSH, local
│   ├── scoring/          # Score calculation
│   └── reporter/         # Output: terminal, JSON
└── internal/checks/      # Check implementations: ssh, firewall, tls, services
```

Checks use the `Collector` interface and never depend on the transport method. Adding a new check means implementing the `Check` interface and registering it.

## Security guarantees

- **Read-only** - never modifies anything on the target
- **No credentials stored** - SSH keys are used in-memory only
- **No phone home** - all processing is local, no external calls
- **Minimal dependencies** - small attack surface

## Roadmap

- [x] SSH, firewall, TLS, exposed services checks
- [x] Scoring system (per-category + overall)
- [x] Terminal and JSON output
- [x] Local audit mode
- [ ] Kubernetes checks (RBAC, network policies, secrets)
- [ ] VPN audit (WireGuard)
- [ ] System audit (updates, kernel, permissions)
- [ ] HTML reports
- [ ] CI/CD integration (GitHub Actions, GitLab CI)
- [ ] Server comparison mode
- [ ] Plugin system for custom checks
- [ ] Web dashboard

## Contributing

Contributions welcome, especially new security checks. See the `Check` interface in `pkg/audit/check.go` for how to add one.

## License

MIT - See [LICENSE](LICENSE) for details.
