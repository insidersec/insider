package analyzers

import (
	"regexp"
	"strings"

	"insider/lexer"
	"insider/visitor"
)

func evaluateNotANDClause(fileContent string, rule lexer.Rule) (shouldReportFinding bool) {
	// The NOT clause is based on the empty result of a RegExp run.
	shouldReportFinding = true

	rulesResults := make([]bool, 0)
	for _, rawNotExpression := range rule.NotAnd {
		expression := regexp.MustCompile(rawNotExpression)
		results := expression.FindAllStringIndex(fileContent, -1)

		if results != nil {
			// If this specific rule found anything, it means that
			// it should not be in the final report.
			rulesResults = append(rulesResults, false)
		} else {
			// Otherwise, it should come in the report
			rulesResults = append(rulesResults, true)
		}
	}

	for _, wasASingleMatch := range rulesResults {
		if wasASingleMatch {
			shouldReportFinding = false
			return
		}
	}

	return
}

func evaluateNotORClause(fileContent string, rule lexer.Rule) (shouldReportFinding bool) {
	shouldReportFinding = true

	for _, rawNotExpression := range rule.NotOr {
		expression := regexp.MustCompile(rawNotExpression)
		findPattern := expression.MatchString(fileContent)

		// If already find something, don't need to evaluate the other one.
		if !findPattern {
			return
		}
	}

	// If we found the pattern intended not to be present
	// we remove this finding from the final report
	shouldReportFinding = false
	return
}

func evaluateNotClauses(fileContent string, rule lexer.Rule) (shouldReportFinding bool) {
	if rule.HaveNotANDClause {
		// Here the original EXPRESSION already found something, so we need to
		shouldReportFinding = evaluateNotANDClause(fileContent, rule)
	} else if rule.HaveNotORClause {
		shouldReportFinding = evaluateNotORClause(fileContent, rule)
	} else {
		shouldReportFinding = true
	}

	return
}

func runNotRule(
	fileInput visitor.InputFile,
	rawExpression string,
	info Info,
	rule lexer.Rule) (findings []Finding, isEmptyMatch bool) {
	isEmptyMatch = false
	expression := regexp.MustCompile(rawExpression)

	if rule.IsBinaryFileRule {
		if !expression.MatchString(fileInput.Content) {
			finding := Finding{
				Info: info,
			}

			isEmptyMatch = false
			findings = append(findings, finding)
		}
	} else {
		results := expression.FindAllStringSubmatchIndex(fileInput.Content, -1)

		if results == nil {
			isEmptyMatch = true
			return
		}

		for _, result := range results {
			fileBasedIndexOfTheFinding := result[0]
			evidence := fileInput.CollectEvidenceSample(fileBasedIndexOfTheFinding)

			finding := Finding{
				Info:   info,
				Line:   evidence.Line,
				Column: evidence.Column,
				Sample: evidence.Sample,
			}

			isEmptyMatch = false
			findings = append(findings, finding)
		}
	}

	return
}

func runSingleRule(fileInput visitor.InputFile, rawExpression string, info Info, rule lexer.Rule) (findings []Finding, isEmptyMatch bool) {
	isEmptyMatch = false
	expression := regexp.MustCompile(rawExpression)

	if rule.IsBinaryFileRule {
		if expression.MatchString(fileInput.Content) {
			finding := Finding{
				Info: info,
			}

			isEmptyMatch = false
			findings = append(findings, finding)
		}
	} else {
		results := expression.FindAllStringIndex(fileInput.Content, -1)

		if results == nil {
			isEmptyMatch = true
			return
		}

		for _, result := range results {
			fileContentFoundByRule := fileInput.Content[result[0]:result[1]]

			shouldReportFinding := evaluateNotClauses(fileContentFoundByRule, rule)

			if !shouldReportFinding {
				isEmptyMatch = true
				return
			}

			fileBasedIndexOfTheFinding := result[0]

			evidence := fileInput.CollectEvidenceSample(fileBasedIndexOfTheFinding)

			finding := Finding{
				Info:            info,
				Line:            evidence.Line,
				Column:          evidence.Column,
				Sample:          evidence.Sample,
				VulnerabilityID: evidence.UniqueHash,
				ScopeName:       evidence.HazardousScope,
			}

			isEmptyMatch = false
			findings = append(findings, finding)
		}
	}

	return
}

func runAndRule(fileInput visitor.InputFile, rule lexer.Rule, info Info) (findings []Finding, isEmptyMatch bool) {
	isEmptyMatch = false
	resultStatus := []bool{}

	parcialFindings := make([]Finding, 0)
	for _, rawExpression := range rule.AndExpressions {
		singleFindings, isSingleEmptyMatch := runSingleRule(fileInput, rawExpression, info, rule)

		resultStatus = append(resultStatus, isSingleEmptyMatch)
		parcialFindings = append(parcialFindings, singleFindings...)
	}

	for _, wasSingleEmptyMatch := range resultStatus {
		if wasSingleEmptyMatch {
			isEmptyMatch = true
			return
		}
	}

	findings = append(findings, parcialFindings...)
	return
}

func runOrRule(fileInput visitor.InputFile, rule lexer.Rule, info Info) (findings []Finding, isEmptyMatch bool) {
	isEmptyMatch = true

	for _, rawExpression := range rule.OrExpressions {
		singleFindings, isSingleEmptyMatch := runSingleRule(fileInput, rawExpression, info, rule)

		if !isSingleEmptyMatch {
			isEmptyMatch = false
			findings = append(findings, singleFindings...)
		}
	}

	return
}

// AnalyzeFile runs all the given rules upon the content and the libraries
func AnalyzeFile(fileInput visitor.InputFile, rules []lexer.Rule) (summary FileSummary) {
	for _, rule := range rules {
		info := Info{
			CWE:           rule.CWE,
			Title:         rule.Title,
			Severity:      rule.Severity,
			CVSS:          rule.AverageCVSS,
			Description:   rule.Description,
			Recomendation: rule.Recomendation,
		}

		if rule.FileFilter != "" {
			if !strings.Contains(fileInput.Name, rule.FileFilter) {
				continue
			}
		}

		summary.Name = fileInput.Name

		if rule.IsAndMatch {
			findingsInRule, isEmptyMatch := runAndRule(fileInput, rule, info)

			if !isEmptyMatch {
				summary.Findings = append(summary.Findings, findingsInRule...)
			}

			continue
		} else if rule.IsOrMatch {
			findingsInRule, isEmptyMatch := runOrRule(fileInput, rule, info)

			if !isEmptyMatch {
				summary.Findings = append(summary.Findings, findingsInRule...)
			}

			continue
		} else if rule.IsNotMatch {
			findingsInRule, isEmptyMatch := runNotRule(fileInput, rule.NotMatch, info, rule)

			if !isEmptyMatch {
				summary.Findings = append(summary.Findings, findingsInRule...)
			}

			continue
		} else {
			findingsInRule, isEmptyMatch := runSingleRule(fileInput, rule.ExactMatch, info, rule)

			if !isEmptyMatch {
				summary.Findings = append(summary.Findings, findingsInRule...)
			}

			continue
		}
	}

	return
}
