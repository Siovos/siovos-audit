// Package reporter defines the output abstraction for presenting audit results.
package reporter

import (
	"io"

	"github.com/Siovos/siovos-audit/pkg/audit"
)

// Reporter formats and writes an audit result to the given writer.
type Reporter interface {
	Report(result *audit.AuditResult, w io.Writer) error
}
