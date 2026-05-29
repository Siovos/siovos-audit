package audit

import (
	"context"

	"github.com/Siovos/siovos-audit/pkg/collector"
)

// Check is the interface that all security checks must implement.
// A check receives a Collector (the transport abstraction) and returns findings.
// It must never calculate scores — that is the Scorer's responsibility.
type Check interface {
	// ID returns a unique identifier for this check (e.g. "ssh", "firewall").
	ID() string
	// Name returns a human-readable name (e.g. "SSH Security").
	Name() string
	// Category returns the scoring category this check belongs to.
	Category() string
	// Run executes the check against the target via the collector.
	Run(ctx context.Context, col collector.Collector) ([]Finding, error)
}
