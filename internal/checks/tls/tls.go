package tls

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/Siovos/siovos-audit/pkg/audit"
	"github.com/Siovos/siovos-audit/pkg/collector"
)

type Check struct{}

func New() *Check { return &Check{} }

func (c *Check) ID() string       { return "tls" }
func (c *Check) Name() string     { return "TLS Certificates" }
func (c *Check) Category() string { return "tls" }

func (c *Check) Run(ctx context.Context, col collector.Collector) ([]audit.Finding, error) {
	var findings []audit.Finding

	certs := findCertificates(ctx, col)
	if len(certs) == 0 {
		return []audit.Finding{{
			ID:       "tls-no-certs",
			CheckID:  "tls",
			Severity: audit.SeverityInfo,
			Title:    "No TLS certificates found",
		}}, nil
	}

	for _, certPath := range certs {
		findings = append(findings, checkCertificate(ctx, col, certPath)...)
	}

	return findings, nil
}

func findCertificates(ctx context.Context, col collector.Collector) []string {
	searchPaths := []string{
		"/etc/letsencrypt/live/*/fullchain.pem",
		"/etc/ssl/certs/ssl-cert-snakeoil.pem",
		"/etc/nginx/ssl/*.pem",
		"/etc/ssl/private/*.crt",
		"/var/lib/rancher/k3s/server/tls/serving-kube-apiserver.crt",
		"/var/lib/rancher/k3s/server/tls/server-ca.crt",
		"/etc/kubernetes/pki/apiserver.crt",
	}

	var found []string
	for _, pattern := range searchPaths {
		out, err := col.Exec(ctx, fmt.Sprintf("ls %s 2>/dev/null", pattern))
		if err != nil {
			continue
		}
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			if line != "" {
				found = append(found, line)
			}
		}
	}
	return found
}

func checkCertificate(ctx context.Context, col collector.Collector, certPath string) []audit.Finding {
	var findings []audit.Finding

	// Check validity
	out, err := col.Exec(ctx, fmt.Sprintf("openssl x509 -in %q -noout -checkend 0 2>&1", certPath))
	if err != nil || strings.Contains(string(out), "will expire") {
		findings = append(findings, audit.Finding{
			ID:          fmt.Sprintf("tls-expired-%s", sanitizePath(certPath)),
			CheckID:     "tls",
			Severity:    audit.SeverityCritical,
			Title:       fmt.Sprintf("Certificate expired: %s", certPath),
			Evidence:    strings.TrimSpace(string(out)),
			Remediation: "Renew the certificate",
		})
		return findings
	}

	findings = append(findings, audit.Finding{
		ID:       fmt.Sprintf("tls-valid-%s", sanitizePath(certPath)),
		CheckID:  "tls",
		Severity: audit.SeverityPass,
		Title:    fmt.Sprintf("Certificate valid: %s", certPath),
	})

	// Check 30-day expiration warning
	out, err = col.Exec(ctx, fmt.Sprintf("openssl x509 -in %q -noout -checkend 2592000 2>&1", certPath))
	if err != nil || strings.Contains(string(out), "will expire") {
		// Get exact days remaining
		daysOut, _ := col.Exec(ctx, fmt.Sprintf(
			`openssl x509 -in %q -noout -enddate 2>/dev/null | cut -d= -f2 | xargs -I{} sh -c 'echo $(( ( $(date -d "{}" +%%s 2>/dev/null || date -j -f "%%b %%d %%H:%%M:%%S %%Y %%Z" "{}" +%%s 2>/dev/null) - $(date +%%s) ) / 86400 ))'`,
			certPath))
		days := strings.TrimSpace(string(daysOut))

		findings = append(findings, audit.Finding{
			ID:       fmt.Sprintf("tls-expiring-%s", sanitizePath(certPath)),
			CheckID:  "tls",
			Severity: audit.SeverityWarn,
			Title:    fmt.Sprintf("Certificate expires within 30 days: %s (%s days left)", certPath, days),
		})
	}

	// Check TLS protocol versions
	out, err = col.Exec(ctx, fmt.Sprintf("openssl x509 -in %q -noout -text 2>/dev/null | grep 'Signature Algorithm'", certPath))
	if err == nil {
		sig := strings.TrimSpace(string(out))
		if strings.Contains(sig, "sha1") {
			findings = append(findings, audit.Finding{
				ID:          fmt.Sprintf("tls-weak-sig-%s", sanitizePath(certPath)),
				CheckID:     "tls",
				Severity:    audit.SeverityFail,
				Title:       fmt.Sprintf("Weak signature algorithm (SHA1): %s", certPath),
				Evidence:    sig,
				Remediation: "Renew with SHA-256 or stronger",
			})
		}
	}

	// Check key size (RSA needs >= 2048, ECDSA >= 256)
	out, err = col.Exec(ctx, fmt.Sprintf("openssl x509 -in %q -noout -text 2>/dev/null | grep -E 'Public-Key|ASN1 OID'", certPath))
	if err == nil {
		keyInfo := strings.TrimSpace(string(out))
		isEC := strings.Contains(keyInfo, "id-ecPublicKey") || strings.Contains(keyInfo, "prime256v1") || strings.Contains(keyInfo, "secp384r1") || strings.Contains(keyInfo, "secp521r1")
		size := extractKeySize(keyInfo)

		if size > 0 && !isEC && size < 2048 {
			findings = append(findings, audit.Finding{
				ID:          fmt.Sprintf("tls-weak-key-%s", sanitizePath(certPath)),
				CheckID:     "tls",
				Severity:    audit.SeverityFail,
				Title:       fmt.Sprintf("Weak RSA key size (%d bit): %s", size, certPath),
				Evidence:    keyInfo,
				Remediation: "Use at least 2048-bit RSA or 256-bit ECDSA",
			})
		}
	}

	return findings
}

func sanitizePath(path string) string {
	r := strings.NewReplacer("/", "-", ".", "-")
	s := r.Replace(path)
	if len(s) > 0 && s[0] == '-' {
		s = s[1:]
	}
	return s
}

func extractKeySize(info string) int {
	// "Public-Key: (2048 bit)" -> 2048
	start := strings.Index(info, "(")
	end := strings.Index(info, " bit")
	if start >= 0 && end > start {
		if n, err := strconv.Atoi(strings.TrimSpace(info[start+1 : end])); err == nil {
			return n
		}
	}
	return 0
}
