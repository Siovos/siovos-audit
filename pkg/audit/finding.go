// Package audit provides the core types and engine for running security audits.
package audit

// Severity represents the severity level of a finding.
type Severity int

const (
	// SeverityPass indicates the check passed successfully.
	SeverityPass Severity = iota
	// SeverityInfo provides informational context, no action needed.
	SeverityInfo
	// SeverityWarn indicates a potential issue that should be reviewed.
	SeverityWarn
	// SeverityFail indicates a security issue that should be fixed.
	SeverityFail
	// SeverityCritical indicates a critical security issue requiring immediate attention.
	SeverityCritical
)

func (s Severity) String() string {
	switch s {
	case SeverityPass:
		return "PASS"
	case SeverityInfo:
		return "INFO"
	case SeverityWarn:
		return "WARN"
	case SeverityFail:
		return "FAIL"
	case SeverityCritical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

// Finding represents a single observation from a security check.
// It is the central data type in the audit pipeline: checks produce findings,
// scorers evaluate them, reporters display them, and stores persist them.
type Finding struct {
	ID          string            `json:"id"`
	CheckID     string            `json:"check_id"`
	Severity    Severity          `json:"severity"`
	Title       string            `json:"title"`
	Description string            `json:"description,omitempty"`
	Evidence    string            `json:"evidence,omitempty"`
	Remediation string            `json:"remediation,omitempty"`
	References  []string          `json:"references,omitempty"`
	Tags        map[string]string `json:"tags,omitempty"`
}
