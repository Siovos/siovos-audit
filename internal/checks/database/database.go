package database

import (
	"context"
	"fmt"
	"strings"

	"github.com/Siovos/siovos-audit/pkg/audit"
	"github.com/Siovos/siovos-audit/pkg/collector"
)

type Check struct{}

func New() *Check { return &Check{} }

func (c *Check) ID() string       { return "database" }
func (c *Check) Name() string     { return "Databases" }
func (c *Check) Category() string { return "database" }

func (c *Check) Run(ctx context.Context, col collector.Collector) ([]audit.Finding, error) {
	var findings []audit.Finding

	findings = append(findings, checkMySQL(ctx, col)...)
	findings = append(findings, checkPostgreSQL(ctx, col)...)
	findings = append(findings, checkRedis(ctx, col)...)
	findings = append(findings, checkMongoDB(ctx, col)...)

	if len(findings) == 0 {
		return []audit.Finding{{
			ID: "db-none", CheckID: "database",
			Severity: audit.SeverityInfo,
			Title:    "No databases detected",
		}}, nil
	}
	return findings, nil
}

func checkMySQL(ctx context.Context, col collector.Collector) []audit.Finding {
	out, err := col.Exec(ctx, "pgrep -x mysqld 2>/dev/null || pgrep -x mariadbd 2>/dev/null")
	if err != nil || strings.TrimSpace(string(out)) == "" {
		return nil
	}

	var findings []audit.Finding
	findings = append(findings, audit.Finding{
		ID: "db-mysql-running", CheckID: "database",
		Severity: audit.SeverityInfo,
		Title:    "MySQL/MariaDB is running",
	})

	// Check bind address
	out, err = col.Exec(ctx, "grep -rE '^\\s*bind-address' /etc/mysql/ 2>/dev/null")
	if err == nil {
		bind := strings.TrimSpace(string(out))
		if strings.Contains(bind, "127.0.0.1") || strings.Contains(bind, "localhost") {
			findings = append(findings, audit.Finding{
				ID: "db-mysql-bind", CheckID: "database",
				Severity: audit.SeverityPass,
				Title:    "MySQL bound to localhost",
			})
		} else {
			findings = append(findings, audit.Finding{
				ID: "db-mysql-bind", CheckID: "database",
				Severity:    audit.SeverityFail,
				Title:       "MySQL not bound to localhost",
				Evidence:    bind,
				Remediation: "Set bind-address = 127.0.0.1 in MySQL config",
			})
		}
	}

	// Check data directory permissions
	out, err = col.Exec(ctx, "stat -c '%a' /var/lib/mysql 2>/dev/null")
	if err == nil {
		perms := strings.TrimSpace(string(out))
		if perms == "700" || perms == "750" {
			findings = append(findings, audit.Finding{
				ID: "db-mysql-data-perms", CheckID: "database",
				Severity: audit.SeverityPass,
				Title:    fmt.Sprintf("MySQL data directory permissions OK (%s)", perms),
			})
		} else {
			findings = append(findings, audit.Finding{
				ID: "db-mysql-data-perms", CheckID: "database",
				Severity:    audit.SeverityWarn,
				Title:       fmt.Sprintf("MySQL data directory too open (%s)", perms),
				Remediation: "chmod 750 /var/lib/mysql",
			})
		}
	}

	return findings
}

func checkPostgreSQL(ctx context.Context, col collector.Collector) []audit.Finding {
	out, err := col.Exec(ctx, "pgrep -x postgres 2>/dev/null || pgrep -x postmaster 2>/dev/null")
	if err != nil || strings.TrimSpace(string(out)) == "" {
		return nil
	}

	var findings []audit.Finding
	findings = append(findings, audit.Finding{
		ID: "db-pg-running", CheckID: "database",
		Severity: audit.SeverityInfo,
		Title:    "PostgreSQL is running",
	})

	// Check listen_addresses
	out, err = col.Exec(ctx, "grep -rE '^\\s*listen_addresses' /etc/postgresql/*/main/postgresql.conf 2>/dev/null")
	if err == nil {
		listen := strings.TrimSpace(string(out))
		if strings.Contains(listen, "localhost") || strings.Contains(listen, "127.0.0.1") {
			findings = append(findings, audit.Finding{
				ID: "db-pg-listen", CheckID: "database",
				Severity: audit.SeverityPass,
				Title:    "PostgreSQL listening on localhost only",
			})
		} else if strings.Contains(listen, "*") {
			findings = append(findings, audit.Finding{
				ID: "db-pg-listen", CheckID: "database",
				Severity:    audit.SeverityFail,
				Title:       "PostgreSQL listening on all interfaces",
				Evidence:    listen,
				Remediation: "Set listen_addresses = 'localhost' in postgresql.conf",
			})
		}
	}

	// Check pg_hba.conf for trust auth
	out, err = col.Exec(ctx, "grep -vE '^\\s*#|^\\s*$' /etc/postgresql/*/main/pg_hba.conf 2>/dev/null | grep trust")
	if err == nil && strings.TrimSpace(string(out)) != "" {
		findings = append(findings, audit.Finding{
			ID: "db-pg-trust", CheckID: "database",
			Severity:    audit.SeverityFail,
			Title:       "PostgreSQL has trust authentication rules",
			Evidence:    strings.TrimSpace(string(out)),
			Remediation: "Replace trust with scram-sha-256 in pg_hba.conf",
		})
	}

	return findings
}

func checkRedis(ctx context.Context, col collector.Collector) []audit.Finding {
	out, err := col.Exec(ctx, "pgrep -x redis-server 2>/dev/null")
	if err != nil || strings.TrimSpace(string(out)) == "" {
		return nil
	}

	var findings []audit.Finding
	findings = append(findings, audit.Finding{
		ID: "db-redis-running", CheckID: "database",
		Severity: audit.SeverityInfo,
		Title:    "Redis is running",
	})

	// Check bind
	out, err = col.Exec(ctx, "grep -E '^\\s*bind' /etc/redis/redis.conf 2>/dev/null || grep -E '^\\s*bind' /etc/redis.conf 2>/dev/null")
	if err == nil {
		bind := strings.TrimSpace(string(out))
		if strings.Contains(bind, "127.0.0.1") {
			findings = append(findings, audit.Finding{
				ID: "db-redis-bind", CheckID: "database",
				Severity: audit.SeverityPass,
				Title:    "Redis bound to localhost",
			})
		} else {
			findings = append(findings, audit.Finding{
				ID: "db-redis-bind", CheckID: "database",
				Severity:    audit.SeverityFail,
				Title:       "Redis not bound to localhost",
				Remediation: "Set bind 127.0.0.1 in redis.conf",
			})
		}
	}

	// Check requirepass
	out, err = col.Exec(ctx, "grep -E '^\\s*requirepass' /etc/redis/redis.conf 2>/dev/null || grep -E '^\\s*requirepass' /etc/redis.conf 2>/dev/null")
	if err != nil || strings.TrimSpace(string(out)) == "" {
		findings = append(findings, audit.Finding{
			ID: "db-redis-auth", CheckID: "database",
			Severity:    audit.SeverityWarn,
			Title:       "Redis has no password (requirepass not set)",
			Remediation: "Set requirepass in redis.conf",
		})
	} else {
		findings = append(findings, audit.Finding{
			ID: "db-redis-auth", CheckID: "database",
			Severity: audit.SeverityPass,
			Title:    "Redis password configured",
		})
	}

	return findings
}

func checkMongoDB(ctx context.Context, col collector.Collector) []audit.Finding {
	out, err := col.Exec(ctx, "pgrep -x mongod 2>/dev/null")
	if err != nil || strings.TrimSpace(string(out)) == "" {
		return nil
	}

	var findings []audit.Finding
	findings = append(findings, audit.Finding{
		ID: "db-mongo-running", CheckID: "database",
		Severity: audit.SeverityInfo,
		Title:    "MongoDB is running",
	})

	// Check authorization
	out, err = col.Exec(ctx, "grep -E 'authorization:\\s*enabled' /etc/mongod.conf 2>/dev/null")
	if err == nil && strings.TrimSpace(string(out)) != "" {
		findings = append(findings, audit.Finding{
			ID: "db-mongo-auth", CheckID: "database",
			Severity: audit.SeverityPass,
			Title:    "MongoDB authorization enabled",
		})
	} else {
		findings = append(findings, audit.Finding{
			ID: "db-mongo-auth", CheckID: "database",
			Severity:    audit.SeverityFail,
			Title:       "MongoDB authorization not enabled",
			Remediation: "Set security.authorization: enabled in /etc/mongod.conf",
		})
	}

	return findings
}
