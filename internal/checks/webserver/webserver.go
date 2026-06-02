package webserver

import (
	"context"
	"strings"

	"github.com/Siovos/siovos-audit/pkg/audit"
	"github.com/Siovos/siovos-audit/pkg/collector"
)

type Check struct{}

func New() *Check { return &Check{} }

func (c *Check) ID() string       { return "webserver" }
func (c *Check) Name() string     { return "Web Server" }
func (c *Check) Category() string { return "webserver" }

func (c *Check) Run(ctx context.Context, col collector.Collector) ([]audit.Finding, error) {
	var findings []audit.Finding

	findings = append(findings, checkNginx(ctx, col)...)
	findings = append(findings, checkApache(ctx, col)...)

	if len(findings) == 0 {
		return []audit.Finding{{
			ID: "web-none", CheckID: "webserver",
			Severity: audit.SeverityInfo,
			Title:    "No web server detected",
		}}, nil
	}
	return findings, nil
}

func checkNginx(ctx context.Context, col collector.Collector) []audit.Finding {
	out, err := col.Exec(ctx, "pgrep -x nginx 2>/dev/null")
	if err != nil || strings.TrimSpace(string(out)) == "" {
		return nil
	}

	var findings []audit.Finding
	findings = append(findings, audit.Finding{
		ID: "web-nginx-running", CheckID: "webserver",
		Severity: audit.SeverityInfo,
		Title:    "Nginx is running",
	})

	// Server tokens
	out, err = col.Exec(ctx, "nginx -T 2>/dev/null | grep -i server_tokens")
	if err == nil {
		val := strings.TrimSpace(string(out))
		if strings.Contains(val, "off") {
			findings = append(findings, audit.Finding{
				ID: "web-nginx-tokens", CheckID: "webserver",
				Severity: audit.SeverityPass,
				Title:    "Nginx server tokens hidden",
			})
		} else {
			findings = append(findings, audit.Finding{
				ID: "web-nginx-tokens", CheckID: "webserver",
				Severity:    audit.SeverityWarn,
				Title:       "Nginx server version exposed",
				Remediation: "Set 'server_tokens off;' in nginx.conf",
			})
		}
	}

	// Access log
	out, err = col.Exec(ctx, "nginx -T 2>/dev/null | grep -i access_log | grep -v off | head -1")
	if err == nil && strings.TrimSpace(string(out)) != "" {
		findings = append(findings, audit.Finding{
			ID: "web-nginx-access-log", CheckID: "webserver",
			Severity: audit.SeverityPass,
			Title:    "Nginx access logging enabled",
		})
	} else {
		findings = append(findings, audit.Finding{
			ID: "web-nginx-access-log", CheckID: "webserver",
			Severity:    audit.SeverityWarn,
			Title:       "Nginx access logging may be disabled",
			Remediation: "Ensure access_log is configured in nginx.conf",
		})
	}

	// Security headers
	out, err = col.Exec(ctx, "nginx -T 2>/dev/null | grep -iE 'X-Frame-Options|X-Content-Type|Content-Security-Policy'")
	if err == nil && strings.TrimSpace(string(out)) != "" {
		findings = append(findings, audit.Finding{
			ID: "web-nginx-headers", CheckID: "webserver",
			Severity: audit.SeverityPass,
			Title:    "Security headers configured",
		})
	} else {
		findings = append(findings, audit.Finding{
			ID: "web-nginx-headers", CheckID: "webserver",
			Severity:    audit.SeverityWarn,
			Title:       "No security headers detected (X-Frame-Options, CSP)",
			Remediation: "Add security headers in nginx configuration",
		})
	}

	// SSL configuration
	out, err = col.Exec(ctx, "nginx -T 2>/dev/null | grep -i ssl_protocols")
	if err == nil {
		val := strings.TrimSpace(string(out))
		if strings.Contains(val, "TLSv1 ") || strings.Contains(val, "TLSv1.1") {
			findings = append(findings, audit.Finding{
				ID: "web-nginx-ssl", CheckID: "webserver",
				Severity:    audit.SeverityFail,
				Title:       "Nginx allows TLS 1.0/1.1 (insecure)",
				Evidence:    val,
				Remediation: "Set 'ssl_protocols TLSv1.2 TLSv1.3;'",
			})
		} else if strings.Contains(val, "TLSv1.3") {
			findings = append(findings, audit.Finding{
				ID: "web-nginx-ssl", CheckID: "webserver",
				Severity: audit.SeverityPass,
				Title:    "Nginx TLS configuration strong",
				Evidence: val,
			})
		}
	}

	return findings
}

func checkApache(ctx context.Context, col collector.Collector) []audit.Finding {
	out, err := col.Exec(ctx, "pgrep -x apache2 2>/dev/null || pgrep -x httpd 2>/dev/null")
	if err != nil || strings.TrimSpace(string(out)) == "" {
		return nil
	}

	var findings []audit.Finding
	findings = append(findings, audit.Finding{
		ID: "web-apache-running", CheckID: "webserver",
		Severity: audit.SeverityInfo,
		Title:    "Apache is running",
	})

	// ServerTokens
	out, err = col.Exec(ctx, "grep -rE '^\\s*ServerTokens' /etc/apache2/ /etc/httpd/ 2>/dev/null")
	if err == nil {
		val := strings.TrimSpace(string(out))
		if strings.Contains(strings.ToLower(val), "prod") {
			findings = append(findings, audit.Finding{
				ID: "web-apache-tokens", CheckID: "webserver",
				Severity: audit.SeverityPass,
				Title:    "Apache ServerTokens set to Prod",
			})
		} else {
			findings = append(findings, audit.Finding{
				ID: "web-apache-tokens", CheckID: "webserver",
				Severity:    audit.SeverityWarn,
				Title:       "Apache server version may be exposed",
				Remediation: "Set 'ServerTokens Prod' in Apache config",
			})
		}
	}

	// TraceEnable
	out, err = col.Exec(ctx, "grep -rE '^\\s*TraceEnable' /etc/apache2/ /etc/httpd/ 2>/dev/null")
	if err == nil && strings.Contains(strings.ToLower(string(out)), "off") {
		findings = append(findings, audit.Finding{
			ID: "web-apache-trace", CheckID: "webserver",
			Severity: audit.SeverityPass,
			Title:    "Apache TRACE method disabled",
		})
	} else {
		findings = append(findings, audit.Finding{
			ID: "web-apache-trace", CheckID: "webserver",
			Severity:    audit.SeverityWarn,
			Title:       "Apache TRACE method may be enabled",
			Remediation: "Set 'TraceEnable Off' in Apache config",
		})
	}

	return findings
}
