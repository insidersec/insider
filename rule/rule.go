package rule

import (
	"regexp"

	"github.com/insidersec/insider/engine"
)

type excludeFn func(content string, rule Rule) (bool, error)

type Rule struct {
	CWE           string
	AverageCVSS   float64
	Title         string
	Severity      string
	Description   string
	Recomendation string

	// And evaluate that each expresion on list is true
	And []*regexp.Regexp

	// Or evaluate that at least one expresion is true
	Or []*regexp.Regexp

	// ExactMatch evaluate that expresion is true
	ExactMatch *regexp.Regexp

	// NotAnd evaluate with ExactMatch, AndExpressions and OrExpressions .
	// If all expresions on list is true the match statement turn to false
	NotAnd []*regexp.Regexp

	// NotOr evaluate with ExactMatch, AndExpressions and OrExpressions.
	// If at least one expresion on list is true the match turn to false
	NotOr []*regexp.Regexp

	// NotMatch evaluate that expresion is false
	NotMatch *regexp.Regexp
}

func (r Rule) Match(inputFile engine.InputFile) ([]engine.Issue, error) {
	issues := make([]engine.Issue, 0)
	info := engine.Info{
		CWE:           r.CWE,
		Title:         r.Title,
		Severity:      r.Severity,
		CVSS:          r.AverageCVSS,
		Description:   r.Description,
		Recomendation: r.Recomendation,
	}

	if r.IsAndMatch() {
		i, err := runAndRule(inputFile, r, info)
		if err != nil {
			return nil, err
		}
		issues = append(issues, i...)
	} else if r.IsOrMatch() {
		i, err := runOrRule(inputFile, r, info)
		if err != nil {
			return nil, err
		}
		issues = append(issues, i...)
	} else if r.IsNotMatch() {
		i, err := runNotRule(inputFile, r.NotMatch, info, r)
		if err != nil {
			return nil, err
		}
		issues = append(issues, i...)
	} else {
		i, err := runSingleRule(inputFile, r.ExactMatch, info, r)
		if err != nil {
			return nil, err
		}
		issues = append(issues, i...)
	}
	return issues, nil
}

func (r Rule) IsMatch() bool {
	return r.ExactMatch != nil
}

func (r Rule) HaveNotORClause() bool {
	return len(r.NotOr) != 0
}

func (r Rule) HaveNotAndClause() bool {
	return len(r.NotAnd) != 0
}

func (r Rule) IsAndMatch() bool {
	return len(r.And) != 0
}

func (r Rule) IsOrMatch() bool {
	return len(r.Or) != 0
}

func (r Rule) IsNotMatch() bool {
	return r.NotMatch != nil
}

func evaluateNotANDClause(content string, rule Rule) (bool, error) {
	finds := 0

	for _, expr := range rule.NotAnd {
		results := expr.FindAllStringIndex(content, -1)

		if results != nil {
			finds++
		}
	}

	return len(rule.NotAnd) != finds, nil
}

func evaluateNotORClause(content string, rule Rule) (bool, error) {
	for _, expr := range rule.NotOr {
		// If already find something, don't need to evaluate the other one.
		if expr.MatchString(content) {
			return false, nil
		}
	}
	return true, nil
}

func evaluateNotClauses(fileContent string, rule Rule) (bool, error) {
	if rule.HaveNotAndClause() {
		return evaluateNotANDClause(fileContent, rule)
	} else if rule.HaveNotORClause() {
		return evaluateNotORClause(fileContent, rule)
	}
	return true, nil
}

func runNotRule(inputFile engine.InputFile, expr *regexp.Regexp, info engine.Info, rule Rule) ([]engine.Issue, error) {
	issues := make([]engine.Issue, 0)

	results := expr.FindAllStringSubmatchIndex(inputFile.Content, -1)

	if results == nil {
		return []engine.Issue{}, nil
	}

	for _, result := range results {
		evidence := inputFile.CollectEvidenceSample(result[0])

		i := engine.Issue{
			Info:            info,
			Line:            evidence.Line,
			Column:          evidence.Column,
			Sample:          evidence.Sample,
			VulnerabilityID: evidence.UniqueHash,
		}

		issues = append(issues, i)
	}

	return issues, nil
}

func runRule(inputFile engine.InputFile, expr *regexp.Regexp, info engine.Info, rule Rule, fn excludeFn) ([]engine.Issue, error) {
	issues := make([]engine.Issue, 0)

	results := expr.FindAllStringIndex(inputFile.Content, -1)
	if results == nil {
		return []engine.Issue{}, nil
	}

	for _, result := range results {
		foundedContent := inputFile.Content[result[0]:result[1]]

		if fn != nil {
			reportIssue, err := fn(foundedContent, rule)
			if err != nil {
				return nil, err
			}
			if !reportIssue {
				return []engine.Issue{}, nil
			}
		}

		evidence := inputFile.CollectEvidenceSample(result[0])
		i := engine.Issue{
			Info:            info,
			Line:            evidence.Line,
			Column:          evidence.Column,
			Sample:          evidence.Sample,
			VulnerabilityID: evidence.UniqueHash,
			Content:         foundedContent,
		}

		issues = append(issues, i)
	}
	return issues, nil
}

func runSingleRule(inputFile engine.InputFile, expr *regexp.Regexp, info engine.Info, r Rule) ([]engine.Issue, error) {
	return runRule(inputFile, expr, info, r, func(content string, r Rule) (bool, error) {
		return evaluateNotClauses(content, r)
	})
}

func runAndRule(inputFile engine.InputFile, rule Rule, info engine.Info) ([]engine.Issue, error) {
	allIssues := make([]engine.Issue, 0)

	for _, expr := range rule.And {
		issues, err := runRule(inputFile, expr, info, rule, nil)
		if err != nil {
			return nil, err
		}
		if len(issues) == 0 {
			return issues, nil
		}
		if rule.HaveNotAndClause() || rule.HaveNotORClause() {
			for _, i := range issues {
				reportIssue, err := evaluateNotClauses(i.Content, rule)
				if err != nil {
					return nil, err
				}

				if reportIssue {
					allIssues = append(allIssues, i)
				}
			}

		} else {
			allIssues = append(allIssues, issues...)
		}
	}
	return allIssues, nil
}

func runOrRule(inputFile engine.InputFile, rule Rule, info engine.Info) ([]engine.Issue, error) {
	issues := make([]engine.Issue, 0)
	for _, rawExpression := range rule.Or {
		i, err := runSingleRule(inputFile, rawExpression, info, rule)
		if err != nil {
			return nil, err
		}

		if i != nil {
			issues = append(issues, i...)
		}
	}
	return issues, nil
}
