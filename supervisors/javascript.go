package supervisors

import (
	"encoding/json"
	"log"

	analyzers "github.com/insidersec/insider/lib"
	"github.com/insidersec/insider/models"
)

// RunJSSourceCodeAnalysis analyzes the given folder and constructs a models.Report.
func RunJSSourceCodeAnalysis(codeInfo SourceCodeInfo) error {
	log.Println("Starting JavaScript source code analysis")

	report := models.Report{}

	err := analyzers.AnalyzeJSSourceCode(codeInfo.PhysicalPath, &report)

	if err != nil {
		log.Println(err.Error())
		return err
	}

	log.Println("Finished JavaScript source code analysis")

	bReport, err := json.Marshal(report)

	if err != nil {
		log.Println(err.Error())
		return err
	}

	err = reportResult(codeInfo, report.Vulnerabilities, bReport)

	if err != nil {
		return err
	}

	log.Printf("Found %d warnings", len(report.Vulnerabilities))

	return nil
}
