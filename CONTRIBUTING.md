# Contributing

Thanks for considering contributing to Siovos Audit. Here's how to get started.

## Setup

```bash
git clone https://github.com/Siovos/siovos-audit.git
cd siovos-audit
make build
make test
```

Requires Go 1.22+.

## Adding a new check

Every check implements the `Check` interface from `pkg/audit/check.go`:

```go
type Check interface {
    ID() string
    Name() string
    Category() string
    Run(ctx context.Context, col collector.Collector) ([]Finding, error)
}
```

Steps:

1. Create a new directory under `internal/checks/yourcheck/`
2. Implement the interface
3. Register it in `cmd/siovos-audit/compare.go` (in `defaultRegistry()`)
4. Add tests

Example skeleton:

```go
package yourcheck

import (
    "context"
    "github.com/Siovos/siovos-audit/pkg/audit"
    "github.com/Siovos/siovos-audit/pkg/collector"
)

type Check struct{}

func New() *Check { return &Check{} }

func (c *Check) ID() string       { return "yourcheck" }
func (c *Check) Name() string     { return "Your Check" }
func (c *Check) Category() string { return "yourcheck" }

func (c *Check) Run(ctx context.Context, col collector.Collector) ([]audit.Finding, error) {
    // Use col.Exec() or col.ReadFile() to gather data
    // Return findings — never calculate scores here
    return nil, nil
}
```

### Rules for checks

- **Read-only**: never modify anything on the target.
- **Transport-agnostic**: use the `Collector` interface, never assume SSH or local.
- **No scoring**: return `Finding` values with appropriate `Severity`. The scorer handles the rest.
- **Include remediation**: tell the user how to fix the issue, not just that it exists.
- **Use Facts for cross-referencing**: call `audit.GetFacts(ctx)` to access shared server state (firewall rules, users, services) instead of re-executing commands.
- **Add explanations**: add an entry in `pkg/explain/explain.go` for your finding IDs so `--explain` provides context.

## Running tests

```bash
make test
```

Tests use mock collectors. See `internal/checks/ssh/ssh_test.go` for an example.

## Pull requests

- Create a branch from `main`
- Keep changes focused — one check or feature per PR
- Tests must pass (`make test`)
- Lint must pass (`golangci-lint run`)

## Severity levels

Use the right severity for your findings:

| Severity | When to use |
|---|---|
| `SeverityPass` | Check passed, no issue |
| `SeverityInfo` | Informational, no action needed |
| `SeverityWarn` | Potential issue, should review |
| `SeverityFail` | Security issue, should fix |
| `SeverityCritical` | Critical issue, fix immediately |

## Questions

Open an issue on GitHub.
