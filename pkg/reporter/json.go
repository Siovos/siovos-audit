package reporter

import (
	"encoding/json"
	"io"

	"github.com/Siovos/siovos-audit/pkg/audit"
)

type JSONReporter struct {
	Pretty bool
}

func NewJSONReporter(pretty bool) *JSONReporter {
	return &JSONReporter{Pretty: pretty}
}

func (r *JSONReporter) Report(result *audit.AuditResult, w io.Writer) error {
	enc := json.NewEncoder(w)
	if r.Pretty {
		enc.SetIndent("", "  ")
	}
	return enc.Encode(result)
}
