package scoring

import "github.com/Siovos/siovos-audit/pkg/audit"

type DefaultScorer struct{}

func NewDefaultScorer() *DefaultScorer {
	return &DefaultScorer{}
}

func (s *DefaultScorer) Score(findings []audit.Finding) audit.ScoreResult {
	categories := make(map[string]*categoryAccumulator)

	for _, f := range findings {
		cat := f.CheckID
		if _, ok := categories[cat]; !ok {
			categories[cat] = &categoryAccumulator{}
		}
		categories[cat].add(f.Severity)
	}

	result := audit.ScoreResult{
		Categories: make(map[string]audit.CategoryScore),
	}

	totalScore := 0
	count := 0

	for name, acc := range categories {
		score := acc.score()
		result.Categories[name] = audit.CategoryScore{
			Name:   name,
			Score:  score,
			Weight: 1.0,
		}
		totalScore += score
		count++
	}

	if count > 0 {
		result.Overall = totalScore / count
	}

	return result
}

type categoryAccumulator struct {
	total    int
	deducted int
}

func (a *categoryAccumulator) add(severity audit.Severity) {
	a.total++
	switch severity {
	case audit.SeverityCritical:
		a.deducted += 25
	case audit.SeverityFail:
		a.deducted += 15
	case audit.SeverityWarn:
		a.deducted += 5
	}
}

func (a *categoryAccumulator) score() int {
	if a.total == 0 {
		return 100
	}
	score := 100 - a.deducted
	if score < 0 {
		return 0
	}
	return score
}
