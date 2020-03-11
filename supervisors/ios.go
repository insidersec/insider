package supervisors

import (
	"encoding/json"
	"log"

	analyzers "github.com/insidersec/insider/lib"
	"github.com/insidersec/insider/models"
)

func RunIOSCodeAnalysis(codeInfo SourceCodeInfo) error {
	log.Println("Starting iOS Source code analysis")

	report := models.IOSReport{}

	log.Println("Extracting libraries")
	libraries, err := analyzers.ExtractLibrariesFromFiles(codeInfo.PhysicalPath)

	if err != nil {
		log.Println(err.Error())
		return err
	}

	report.Libraries = libraries

	err = analyzers.AnalyzeIOSSource(codeInfo.PhysicalPath, &report)

	if err != nil {
		log.Println(err.Error())

		return err
	}

	log.Println("Finished code analysis")

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
