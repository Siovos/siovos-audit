package audit_test

import (
	"context"
	"testing"

	"github.com/Siovos/siovos-audit/pkg/audit"
	"github.com/Siovos/siovos-audit/pkg/collector"
)

type stubCheck struct {
	id       string
	name     string
	category string
}

func (c *stubCheck) ID() string       { return c.id }
func (c *stubCheck) Name() string     { return c.name }
func (c *stubCheck) Category() string { return c.category }
func (c *stubCheck) Run(_ context.Context, _ collector.Collector) ([]audit.Finding, error) {
	return nil, nil
}

func TestRegistry_RegisterAndGet(t *testing.T) {
	r := audit.NewRegistry()
	c := &stubCheck{id: "ssh", name: "SSH", category: "ssh"}

	r.Register(c)

	got, ok := r.Get("ssh")
	if !ok {
		t.Fatal("expected to find check 'ssh'")
	}
	if got.ID() != "ssh" {
		t.Errorf("got ID %q, want %q", got.ID(), "ssh")
	}
}

func TestRegistry_DuplicateRegister(t *testing.T) {
	r := audit.NewRegistry()
	c1 := &stubCheck{id: "ssh", name: "SSH v1"}
	c2 := &stubCheck{id: "ssh", name: "SSH v2"}

	r.Register(c1)
	r.Register(c2)

	if len(r.All()) != 1 {
		t.Errorf("got %d checks, want 1", len(r.All()))
	}
	got, _ := r.Get("ssh")
	if got.Name() != "SSH v1" {
		t.Error("duplicate register should keep the first check")
	}
}

func TestRegistry_FilterEmpty(t *testing.T) {
	r := audit.NewRegistry()
	r.Register(&stubCheck{id: "ssh"})
	r.Register(&stubCheck{id: "tls"})

	// Empty filter returns all
	all := r.Filter(nil)
	if len(all) != 2 {
		t.Errorf("got %d checks, want 2", len(all))
	}
}

func TestRegistry_FilterByID(t *testing.T) {
	r := audit.NewRegistry()
	r.Register(&stubCheck{id: "ssh"})
	r.Register(&stubCheck{id: "tls"})
	r.Register(&stubCheck{id: "firewall"})

	filtered := r.Filter([]string{"ssh", "firewall"})
	if len(filtered) != 2 {
		t.Errorf("got %d checks, want 2", len(filtered))
	}
}

func TestRegistry_FilterUnknown(t *testing.T) {
	r := audit.NewRegistry()
	r.Register(&stubCheck{id: "ssh"})

	filtered := r.Filter([]string{"nonexistent"})
	if len(filtered) != 0 {
		t.Errorf("got %d checks, want 0", len(filtered))
	}
}
