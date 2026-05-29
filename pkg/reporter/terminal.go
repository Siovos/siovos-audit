package reporter

import (
	"fmt"
	"io"
	"strings"

	"github.com/Siovos/siovos-audit/pkg/audit"
)

const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorCyan   = "\033[36m"
	colorBold   = "\033[1m"
	colorDim    = "\033[2m"
)

type TerminalReporter struct{}

func NewTerminalReporter() *TerminalReporter {
	return &TerminalReporter{}
}

func (r *TerminalReporter) Report(result *audit.AuditResult, w io.Writer) error {
	fmt.Fprintf(w, "\n  %sSiovos Audit%s\n", colorBold, colorReset)
	fmt.Fprintf(w, "  %sTarget: %s%s", colorDim, result.Target, colorReset)
	if result.Platform.Distro != "" {
		fmt.Fprintf(w, " (%s)", result.Platform.Distro)
	}
	fmt.Fprintf(w, "\n\n")

	grouped := groupByCheck(result.Findings)

	for _, cat := range sortedCategories(result.Score.Categories) {
		score := result.Score.Categories[cat]
		dots := strings.Repeat(".", 40-len(score.Name))
		scoreColor := scoreToColor(score.Score)
		fmt.Fprintf(w, "  %s%s%s %s %s%d/100%s\n", colorBold, score.Name, colorReset, dots, scoreColor, score.Score, colorReset)

		if findings, ok := grouped[cat]; ok {
			for _, f := range findings {
				tag := severityTag(f.Severity)
				fmt.Fprintf(w, "    %s %s\n", tag, f.Title)
			}
		}
		fmt.Fprintln(w)
	}

	overallColor := scoreToColor(result.Score.Overall)
	fmt.Fprintf(w, "  %sOverall Score: %s%d/100%s\n", colorBold, overallColor, result.Score.Overall, colorReset)

	fails, warns := countIssues(result.Findings)
	if fails > 0 || warns > 0 {
		fmt.Fprintf(w, "  %s%d issues to fix%s, %s%d warnings to review%s\n",
			colorRed, fails, colorReset,
			colorYellow, warns, colorReset)
	}
	fmt.Fprintln(w)

	return nil
}

func severityTag(s audit.Severity) string {
	switch s {
	case audit.SeverityPass:
		return colorGreen + "[PASS]" + colorReset
	case audit.SeverityInfo:
		return colorBlue + "[INFO]" + colorReset
	case audit.SeverityWarn:
		return colorYellow + "[WARN]" + colorReset
	case audit.SeverityFail:
		return colorRed + "[FAIL]" + colorReset
	case audit.SeverityCritical:
		return colorRed + colorBold + "[CRIT]" + colorReset
	default:
		return "[????]"
	}
}

func scoreToColor(score int) string {
	switch {
	case score >= 80:
		return colorGreen
	case score >= 60:
		return colorYellow
	default:
		return colorRed
	}
}

func groupByCheck(findings []audit.Finding) map[string][]audit.Finding {
	grouped := make(map[string][]audit.Finding)
	for _, f := range findings {
		grouped[f.CheckID] = append(grouped[f.CheckID], f)
	}
	return grouped
}

func sortedCategories(categories map[string]audit.CategoryScore) []string {
	keys := make([]string, 0, len(categories))
	for k := range categories {
		keys = append(keys, k)
	}
	// Simple sort for deterministic output
	for i := 0; i < len(keys); i++ {
		for j := i + 1; j < len(keys); j++ {
			if keys[i] > keys[j] {
				keys[i], keys[j] = keys[j], keys[i]
			}
		}
	}
	return keys
}

func countIssues(findings []audit.Finding) (fails, warns int) {
	for _, f := range findings {
		switch f.Severity {
		case audit.SeverityFail, audit.SeverityCritical:
			fails++
		case audit.SeverityWarn:
			warns++
		}
	}
	return
}
