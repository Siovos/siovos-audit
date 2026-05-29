package kubernetes_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/Siovos/siovos-audit/internal/checks/kubernetes"
	"github.com/Siovos/siovos-audit/pkg/audit"
	"github.com/Siovos/siovos-audit/pkg/collector"
)

type mockCollector struct {
	commands map[string]string
}

func (m *mockCollector) Exec(_ context.Context, cmd string) ([]byte, error) {
	if out, ok := m.commands[cmd]; ok {
		return []byte(out), nil
	}
	return nil, fmt.Errorf("command not found")
}
func (m *mockCollector) ReadFile(_ context.Context, _ string) ([]byte, error) {
	return nil, fmt.Errorf("not implemented")
}
func (m *mockCollector) Platform() collector.Platform { return collector.Platform{OS: "linux"} }
func (m *mockCollector) Target() string               { return "test" }
func (m *mockCollector) Close() error                  { return nil }

func TestKubernetes_NotDetected(t *testing.T) {
	col := &mockCollector{commands: map[string]string{}}

	c := kubernetes.New()
	findings, err := c.Run(context.Background(), col)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].Severity != audit.SeverityInfo {
		t.Error("expected single INFO finding when K8s not detected")
	}
}

func TestKubernetes_RBACEnabled(t *testing.T) {
	col := &mockCollector{commands: map[string]string{
		"kubectl version --client=false --short 2>/dev/null || k3s kubectl version --short 2>/dev/null": "Server Version: v1.28.0",
		"kubectl api-versions 2>/dev/null": "rbac.authorization.k8s.io/v1\napps/v1\nv1",
		"kubectl get networkpolicies --all-namespaces --no-headers 2>/dev/null": "default   deny-all   <none>   5d",
		"ss -tlnp 2>/dev/null | grep 6443": "LISTEN 0 128 127.0.0.1:6443 0.0.0.0:*",
	}}

	c := kubernetes.New()
	findings, err := c.Run(context.Background(), col)
	if err != nil {
		t.Fatal(err)
	}

	for _, f := range findings {
		if f.ID == "k8s-rbac" && f.Severity != audit.SeverityPass {
			t.Errorf("RBAC should be PASS, got %s", f.Severity)
		}
		if f.ID == "k8s-network-policies" && f.Severity != audit.SeverityPass {
			t.Errorf("network policies should be PASS, got %s", f.Severity)
		}
	}
}

func TestKubernetes_NoNetworkPolicies(t *testing.T) {
	col := &mockCollector{commands: map[string]string{
		"kubectl version --client=false --short 2>/dev/null || k3s kubectl version --short 2>/dev/null": "Server Version: v1.28.0",
		"kubectl api-versions 2>/dev/null": "rbac.authorization.k8s.io/v1",
		"kubectl get networkpolicies --all-namespaces --no-headers 2>/dev/null": "",
	}}

	c := kubernetes.New()
	findings, err := c.Run(context.Background(), col)
	if err != nil {
		t.Fatal(err)
	}

	for _, f := range findings {
		if f.ID == "k8s-network-policies" && f.Severity != audit.SeverityWarn {
			t.Errorf("no network policies should be WARN, got %s", f.Severity)
		}
	}
}
