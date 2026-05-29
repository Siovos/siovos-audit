package audit

import "time"

// AuditSummary is a lightweight view of an audit result for listing.
type AuditSummary struct {
	ID        string    `json:"id"`
	Target    string    `json:"target"`
	Score     int       `json:"score"`
	Timestamp time.Time `json:"timestamp"`
}
