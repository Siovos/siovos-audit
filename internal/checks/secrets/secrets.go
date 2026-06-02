package secrets

import (
	"context"
	"fmt"
	"strings"

	"github.com/Siovos/siovos-audit/pkg/audit"
	"github.com/Siovos/siovos-audit/pkg/collector"
)

type Check struct{}

func New() *Check { return &Check{} }

func (c *Check) ID() string       { return "secrets" }
func (c *Check) Name() string     { return "Exposed Secrets" }
func (c *Check) Category() string { return "secrets" }

func (c *Check) Run(ctx context.Context, col collector.Collector) ([]audit.Finding, error) {
	var findings []audit.Finding

	findings = append(findings, checkEnvFiles(ctx, col)...)
	findings = append(findings, checkGitExposed(ctx, col)...)
	findings = append(findings, checkConfigSecrets(ctx, col)...)
	findings = append(findings, checkSSHKeyPermissions(ctx, col)...)

	if len(findings) == 0 {
		findings = append(findings, audit.Finding{
			ID: "secrets-none", CheckID: "secrets",
			Severity: audit.SeverityPass,
			Title:    "No exposed secrets detected",
		})
	}
	return findings, nil
}

func checkEnvFiles(ctx context.Context, col collector.Collector) []audit.Finding {
	paths := []string{"/var/www", "/srv", "/opt", "/home"}
	var findings []audit.Finding

	for _, base := range paths {
		out, err := col.Exec(ctx, fmt.Sprintf("find %s -maxdepth 4 -name '.env' -type f 2>/dev/null | head -10", base))
		if err != nil || strings.TrimSpace(string(out)) == "" {
			continue
		}
		for _, f := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			if f == "" {
				continue
			}
			findings = append(findings, audit.Finding{
				ID:          "secrets-env-" + sanitize(f),
				CheckID:     "secrets",
				Severity:    audit.SeverityWarn,
				Title:       fmt.Sprintf(".env file found: %s", f),
				Remediation: "Ensure .env files are not accessible via web server. Check permissions and webroot config.",
			})
		}
	}
	return findings
}

func checkGitExposed(ctx context.Context, col collector.Collector) []audit.Finding {
	webroots := []string{"/var/www/html", "/var/www", "/srv/www", "/usr/share/nginx/html"}
	var findings []audit.Finding

	for _, root := range webroots {
		out, err := col.Exec(ctx, fmt.Sprintf("test -d %s/.git && echo found 2>/dev/null", root))
		if err == nil && strings.Contains(string(out), "found") {
			findings = append(findings, audit.Finding{
				ID:          "secrets-git-" + sanitize(root),
				CheckID:     "secrets",
				Severity:    audit.SeverityCritical,
				Title:       fmt.Sprintf(".git directory in webroot: %s", root),
				Remediation: fmt.Sprintf("Remove .git from webroot or deny access in web server config:\n  location ~ /\\.git { deny all; }"),
			})
		}
	}
	return findings
}

func checkConfigSecrets(ctx context.Context, col collector.Collector) []audit.Finding {
	// Search for common patterns in config files
	patterns := []struct {
		grep string
		name string
	}{
		{`grep -rlE 'password\s*=\s*[^$]' /etc/ 2>/dev/null | grep -v shadow | grep -v pam | head -5`, "password in /etc/"},
		{`find /var/www /srv /opt -maxdepth 3 -name 'wp-config.php' 2>/dev/null | head -3`, "WordPress config"},
		{`find /var/www /srv /opt -maxdepth 3 -name 'database.yml' 2>/dev/null | head -3`, "Rails database config"},
		{`find /var/www /srv /opt -maxdepth 3 -name '.htpasswd' 2>/dev/null | head -3`, ".htpasswd file"},
	}

	var findings []audit.Finding
	for _, p := range patterns {
		out, err := col.Exec(ctx, p.grep)
		if err != nil || strings.TrimSpace(string(out)) == "" {
			continue
		}
		files := strings.Split(strings.TrimSpace(string(out)), "\n")
		findings = append(findings, audit.Finding{
			ID:       "secrets-config-" + sanitize(p.name),
			CheckID:  "secrets",
			Severity: audit.SeverityInfo,
			Title:    fmt.Sprintf("%s found (%d files)", p.name, len(files)),
			Evidence: strings.TrimSpace(string(out)),
		})
	}
	return findings
}

func checkSSHKeyPermissions(ctx context.Context, col collector.Collector) []audit.Finding {
	out, err := col.Exec(ctx, "find /home /root -maxdepth 3 -name 'id_*' -not -name '*.pub' 2>/dev/null")
	if err != nil || strings.TrimSpace(string(out)) == "" {
		return nil
	}

	var findings []audit.Finding
	for _, keyPath := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if keyPath == "" {
			continue
		}
		permOut, err := col.Exec(ctx, fmt.Sprintf("stat -c '%%a' %q 2>/dev/null", keyPath))
		if err != nil {
			continue
		}
		perms := strings.TrimSpace(string(permOut))
		if perms != "600" && perms != "400" {
			findings = append(findings, audit.Finding{
				ID:          "secrets-sshkey-" + sanitize(keyPath),
				CheckID:     "secrets",
				Severity:    audit.SeverityFail,
				Title:       fmt.Sprintf("SSH private key too permissive: %s (%s)", keyPath, perms),
				Remediation: fmt.Sprintf("chmod 600 %s", keyPath),
			})
		}
	}
	return findings
}

func sanitize(s string) string {
	r := strings.NewReplacer("/", "-", ".", "-", " ", "-")
	result := r.Replace(strings.ToLower(s))
	if len(result) > 0 && result[0] == '-' {
		result = result[1:]
	}
	if len(result) > 40 {
		result = result[:40]
	}
	return result
}
