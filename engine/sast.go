package engine

// Info holds data about the current rule been evaluated
type Info struct {
	Description   string
	CWE           string
	CVSS          float64
	Severity      string
	Title         string
	Recomendation string
}

// Issue represents a issue found in the source code
type Issue struct {
	VulnerabilityID string
	Line            int
	Info            Info
	Column          int
	Sample          string
	Content         string
}

// AnalyzeFile runs all the given rules upon the content and the libraries
func AnalyzeFile(inputFile InputFile, rules []Rule) ([]Issue, error) {
	issues := make([]Issue, 0)
	for _, rule := range rules {
		i, err := rule.Match(inputFile)
		if err != nil {
			return nil, err
		}
		if i != nil {
			issues = append(issues, i...)
		}
	}

	return issues, nil
}

// CalculateSecurityScore calculate the Security Score for the whole report
func CalculateSecurityScore(highestCVSS float64) float64 {
	return float64(100 - int(highestCVSS*10))
}
