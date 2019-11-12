package supervisors

import (
	"encoding/json"
	"log"

	analyzers "github.com/insidersec/insider/lib"
	"github.com/insidersec/insider/models"
)

// RunAndroidSourceCodeAnalysis analyzes the given folder and constructs a models.AndroidReport.
func RunAndroidSourceCodeAnalysis(codeInfo SourceCodeInfo) error {
	log.Println("Starting Android source code analysis")

	report := models.AndroidReport{}

	log.Println("Starting Android Manifest analysis")

	err := analyzers.AnalyzeAndroidManifest(codeInfo.PhysicalPath, &report)

	log.Println("Finished Android Manifest analysis")

	if err != nil {
		return err
	}

	err = analyzers.AnalyzeAndroidSource(codeInfo.PhysicalPath, &report)

	log.Println("Finished Android source Code analysis")

	if err != nil {
		return err
	}

	bReport, err := json.Marshal(report)

	if err != nil {
		return err
	}

	err = reportResult(codeInfo, report.Vulnerabilities, bReport)

	if err != nil {
		return err
	}

	log.Printf("Found %d warnings", len(report.Vulnerabilities))

	return nil
}
