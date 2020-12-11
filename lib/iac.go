package lib

import (
	"fmt"
	"strconv"

	"github.com/insidersec/insider/analyzers"
	"github.com/insidersec/insider/lexer"
	"github.com/insidersec/insider/models/reports"
	"github.com/insidersec/insider/visitor"
)

// AnalyzeIaCCode runs queries against the given folder of IaC code
func AnalyzeIaCCode(dirname, sastID string, report *reports.Report) error {
	files, err := visitor.LoadSourceDir(dirname, "iac")

	if err != nil {
		return err
	}

	rules, err := lexer.LoadIaCRules()

	if err != nil {
		return err
	}

	appSize, err := analyzers.GetUnpackedAppSize(dirname)

	if err != nil {
		return err
	}

	report.Info.Size = fmt.Sprintf("%s MB", strconv.Itoa(appSize))

	for _, file := range files {
		fileForAnalyze, err := visitor.ParseCloudFormationTemplate(file)

		if err != nil {
			return err
		}

		results := analyzers.RunQueries(fileForAnalyze, rules)

		for _, queryResult := range results {
			for _, finding := range queryResult.Findings {
				vulnerability := reports.Vulnerability{
					ClassMessage: file,
					LongMessage:  finding.Message,
					Method:       finding.AffectedNode,
				}

				vulnerability.SastID = sastID

				report.Vulnerabilities = append(report.Vulnerabilities, vulnerability)
			}

			for _, failMessage := range queryResult.Errors {
				vulnerability := reports.Vulnerability{
					LongMessage:  failMessage,
					ClassMessage: file,
				}

				vulnerability.SastID = sastID

				report.Vulnerabilities = append(report.Vulnerabilities, vulnerability)
			}
		}
	}

	report.Info.SastID = sastID

	return nil
}
