// Package store provides persistence for audit results.
package store

import "github.com/Siovos/siovos-audit/pkg/audit"

// Store persists and retrieves audit results.
type Store interface {
	Save(result *audit.AuditResult) error
	Load(id string) (*audit.AuditResult, error)
	List() ([]audit.AuditSummary, error)
	ListByTarget(target string) ([]audit.AuditSummary, error)
}
