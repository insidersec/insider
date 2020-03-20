package analyzers

import (
	"regexp"
	"strings"
	"github.com/insidersec/insider/lexer"
	"github.com/insidersec/insider/models"
)

func evaluateNotANDClause(file lexer.InputFile, rule lexer.Rule) (shouldReportFinding bool) {
	// The NOT clause is based on the empty result of a RegExp run.
	shouldReportFinding = true

	rulesResults := make([]bool, 0)
	for _, rawNotExpression := range rule.NotAnd {
		expression := regexp.MustCompile(rawNotExpression)
		results := expression.FindAllStringIndex(file.Content, -1)

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

func evaluateNotORClause(file lexer.InputFile, rule lexer.Rule) (shouldReportFinding bool) {
	shouldReportFinding = true

	for _, rawNotExpression := range rule.NotOr {
		expression := regexp.MustCompile(rawNotExpression)
		results := expression.FindAllStringIndex(file.Content, -1)

		// If already find something, don't need to evaluate the other one.
		// @TODO: Maybe we should run all of them? :thinking_face:
		if results == nil {
			return
		}
	}

	shouldReportFinding = false
	return
}

func evaluateNotClauses(file lexer.InputFile, rule lexer.Rule) (shouldReportFinding bool) {
	if rule.HaveNotANDClause {
		// Here the original EXPRESSION already found something, so we need to
		shouldReportFinding = evaluateNotANDClause(file, rule)
	} else if rule.HaveNotORClause {
		shouldReportFinding = evaluateNotORClause(file, rule)
	} else {
		shouldReportFinding = true
	}

	return
}

func runNotRule(
	fileInput lexer.InputFile,
	rawExpression string,
	info models.Info,
	rule lexer.Rule) (findings []models.Finding, isEmptyMatch bool) {
	isEmptyMatch = false
	expression := regexp.MustCompile(rawExpression)

	if rule.IsBinaryFileRule {
		if !expression.MatchString(fileInput.Content) {
			finding := models.Finding{
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

			finding := models.Finding{
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

func runSingleRule(
	fileInput lexer.InputFile,
	rawExpression string,
	info models.Info,
	rule lexer.Rule) (findings []models.Finding, isEmptyMatch bool) {
	isEmptyMatch = false
	expression := regexp.MustCompile(rawExpression)

	if rule.IsBinaryFileRule {
		if expression.MatchString(fileInput.Content) {
			finding := models.Finding{
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
			fileBasedIndexOfTheFinding := result[0]
			evidence := fileInput.CollectEvidenceSample(fileBasedIndexOfTheFinding)

			finding := models.Finding{
				Info:   info,
				Line:   evidence.Line,
				Column: evidence.Column,
				Sample: evidence.Sample,
			}

			isEmptyMatch = false
			findings = append(findings, finding)
		}
	}

	if len(rule.Libraries) > 0 {
		for _, ruleLibrary := range rule.Libraries {
			isLibraryUsed := IsLibraryUsed(fileInput.Libraries, ruleLibrary)

			if !isLibraryUsed {
				isEmptyMatch = true
				return
			}
		}
	}

	if len(rule.Permissions) > 0 {
		for _, rulePermission := range rule.Permissions {
			isPermissionRequired := IsUsed(fileInput.Permissions, rulePermission)

			if !isPermissionRequired {
				isEmptyMatch = true
				return
			}
		}
	}

	shouldReportFinding := evaluateNotClauses(fileInput, rule)

	if !shouldReportFinding {
		isEmptyMatch = true
		return
	}

	return
}

func runAndRule(fileInput lexer.InputFile, rule lexer.Rule, info models.Info) (findings []models.Finding, isEmptyMatch bool) {
	isEmptyMatch = false
	resultStatus := []bool{}

	parcialFindings := make([]models.Finding, 0)
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

func runOrRule(fileInput lexer.InputFile, rule lexer.Rule, info models.Info) (findings []models.Finding, isEmptyMatch bool) {
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
func AnalyzeFile(fileInput lexer.InputFile, rules []lexer.Rule) (summary models.FileSummary) {
	for _, rule := range rules {
		info := models.Info{
			CWE:              rule.CWE,
			Title:            rule.Title,
			Severity:         rule.Severity,
			Description:      rule.Description,
			Recomendation:    rule.Recomendation,
			OWASPReferenceID: rule.OWASPReferenceID,
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
