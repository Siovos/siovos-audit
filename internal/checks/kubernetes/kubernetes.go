package kubernetes

import (
	"context"
	"fmt"
	"strings"

	"github.com/Siovos/siovos-audit/pkg/audit"
	"github.com/Siovos/siovos-audit/pkg/collector"
)

type Check struct{}

func New() *Check { return &Check{} }

func (c *Check) ID() string       { return "kubernetes" }
func (c *Check) Name() string     { return "Kubernetes" }
func (c *Check) Category() string { return "kubernetes" }

func (c *Check) Run(ctx context.Context, col collector.Collector) ([]audit.Finding, error) {
	// Detect if K8s is present
	out, err := col.Exec(ctx, "kubectl version --client=false --short 2>/dev/null || k3s kubectl version --short 2>/dev/null")
	if err != nil || strings.TrimSpace(string(out)) == "" {
		return []audit.Finding{{
			ID:       "k8s-not-found",
			CheckID:  "kubernetes",
			Severity: audit.SeverityInfo,
			Title:    "Kubernetes not detected on this server",
		}}, nil
	}

	var findings []audit.Finding
	findings = append(findings, checkRBAC(ctx, col)...)
	findings = append(findings, checkNetworkPolicies(ctx, col)...)
	findings = append(findings, checkSecretsEncryption(ctx, col)...)
	findings = append(findings, checkAPIServerExposure(ctx, col)...)
	findings = append(findings, checkPodsRunningAsRoot(ctx, col)...)

	return findings, nil
}

func checkRBAC(ctx context.Context, col collector.Collector) []audit.Finding {
	out, err := col.Exec(ctx, "kubectl api-versions 2>/dev/null")
	if err != nil {
		return nil
	}

	if strings.Contains(string(out), "rbac.authorization.k8s.io") {
		return []audit.Finding{{
			ID:       "k8s-rbac",
			CheckID:  "kubernetes",
			Severity: audit.SeverityPass,
			Title:    "RBAC enabled",
		}}
	}

	return []audit.Finding{{
		ID:          "k8s-rbac",
		CheckID:     "kubernetes",
		Severity:    audit.SeverityFail,
		Title:       "RBAC not enabled",
		Remediation: "Enable RBAC on the API server with --authorization-mode=RBAC",
		References:  []string{"CIS 1.2.7"},
	}}
}

func checkNetworkPolicies(ctx context.Context, col collector.Collector) []audit.Finding {
	out, err := col.Exec(ctx, "kubectl get networkpolicies --all-namespaces --no-headers 2>/dev/null")
	if err != nil {
		return nil
	}

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) == 0 || (len(lines) == 1 && lines[0] == "") {
		return []audit.Finding{{
			ID:          "k8s-network-policies",
			CheckID:     "kubernetes",
			Severity:    audit.SeverityWarn,
			Title:       "No network policies defined",
			Remediation: "Define NetworkPolicy resources to restrict pod-to-pod traffic",
			References:  []string{"CIS 5.3.2"},
		}}
	}

	return []audit.Finding{{
		ID:       "k8s-network-policies",
		CheckID:  "kubernetes",
		Severity: audit.SeverityPass,
		Title:    "Network policies defined",
		Evidence: strings.TrimSpace(string(out)),
	}}
}

func checkSecretsEncryption(ctx context.Context, col collector.Collector) []audit.Finding {
	// Check if encryption config exists (common paths)
	paths := []string{
		"/etc/kubernetes/encryption-config.yaml",
		"/var/lib/rancher/k3s/server/cred/encryption-config.json",
	}

	for _, path := range paths {
		out, err := col.Exec(ctx, "test -f "+path+" && echo found 2>/dev/null")
		if err == nil && strings.Contains(string(out), "found") {
			return []audit.Finding{{
				ID:       "k8s-secrets-encryption",
				CheckID:  "kubernetes",
				Severity: audit.SeverityPass,
				Title:    "Secrets encryption at rest configured",
				Evidence: "Encryption config found at " + path,
			}}
		}
	}

	return []audit.Finding{{
		ID:          "k8s-secrets-encryption",
		CheckID:     "kubernetes",
		Severity:    audit.SeverityWarn,
		Title:       "Secrets encryption at rest not detected",
		Remediation: "Configure encryption at rest for secrets: https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/",
		References:  []string{"CIS 1.2.29"},
	}}
}

func checkAPIServerExposure(ctx context.Context, col collector.Collector) []audit.Finding {
	out, err := col.Exec(ctx, "ss -tlnp 2>/dev/null | grep 6443")
	if err != nil {
		return nil
	}

	output := string(out)
	if strings.Contains(output, "0.0.0.0:6443") || strings.Contains(output, ":::6443") {
		return []audit.Finding{{
			ID:          "k8s-api-exposure",
			CheckID:     "kubernetes",
			Severity:    audit.SeverityWarn,
			Title:       "API server listening on all interfaces (port 6443)",
			Remediation: "Bind API server to internal interface or restrict access with firewall rules",
		}}
	}

	return []audit.Finding{{
		ID:       "k8s-api-exposure",
		CheckID:  "kubernetes",
		Severity: audit.SeverityPass,
		Title:    "API server not exposed on all interfaces",
	}}
}

func checkPodsRunningAsRoot(ctx context.Context, col collector.Collector) []audit.Finding {
	out, err := col.Exec(ctx, `kubectl get pods --all-namespaces -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}{"\t"}{range .spec.containers[*]}{.securityContext.runAsUser}{"\t"}{end}{"\n"}{end}' 2>/dev/null`)
	if err != nil {
		return nil
	}

	rootCount := 0
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		for _, f := range fields[1:] {
			if f == "0" {
				rootCount++
			}
		}
	}

	if rootCount > 0 {
		return []audit.Finding{{
			ID:          "k8s-pods-root",
			CheckID:     "kubernetes",
			Severity:    audit.SeverityWarn,
			Title:       pluralize(rootCount, "pod running as root", "pods running as root"),
			Remediation: "Set securityContext.runAsNonRoot: true in pod specs",
			References:  []string{"CIS 5.2.6"},
		}}
	}

	return []audit.Finding{{
		ID:       "k8s-pods-root",
		CheckID:  "kubernetes",
		Severity: audit.SeverityPass,
		Title:    "No pods running as root",
	}}
}

func pluralize(n int, singular, plural string) string {
	if n == 1 {
		return "1 " + singular
	}
	return fmt.Sprintf("%d %s", n, plural)
}
