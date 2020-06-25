package supervisors

import (
	"encoding/json"
	"insider/export"
	analyzers "insider/lib"
	"insider/models/reports"
	"insider/util"
	"log"
)

// RunAndroidSourceCodeAnalysis analyzes the given folder and constructs a models.AndroidReport.
func RunAndroidSourceCodeAnalysis(codeInfo SourceCodeInfo, lang string, destinationFolder string, noJSON bool, noHTML bool, security int, verbose bool, ignoreWarnings bool) error {
	log.Println("Starting Android source code analysis")

	report := reports.AndroidReport{}

	report.AndroidInfo.MD5 = codeInfo.MD5Hash
	report.AndroidInfo.SHA1 = codeInfo.SHA1Hash
	report.AndroidInfo.SHA256 = codeInfo.SHA256Hash

	log.Println("Starting Android Manifest analysis")
	err := analyzers.AnalyzeAndroidManifest(destinationFolder, codeInfo.SastID, &report, lang)

	if err != nil {
		log.Printf("Error: %s", err.Error())
		return err
	}
	log.Println("Finished Android Manifest analysis")

	log.Println("Starting Android Source Code Analysis")
	err = analyzers.AnalyzeAndroidSource(destinationFolder, codeInfo.SastID, &report, lang)
	if err != nil {
		log.Printf("Error: %s", err.Error())
		return err
	}

	util.CheckSecurityScore(security, int(report.AndroidInfo.SecurityScore))

	log.Println("Finished Android source Code analysis")

	bReport, err := json.Marshal(report)
	log.Println("Report Done")
	//log.Println(string(bReport))

	if err != nil {
		log.Printf("Error: %s", err.Error())
		return err
	}

	r := reports.DoHtmlReport(report)

	if verbose {
		reports.ConsoleReport(r)
	}

	if noJSON {
		log.Println("No Json report")
	} else {
		err = reportResult(bReport, ignoreWarnings)
		if err != nil {
			return err
		}
	}

	if noHTML {
		log.Println("No Html report")
	} else {
		export.ToHtml(r, lang, ignoreWarnings)
	}
	if err != nil {
		log.Printf("Error: %s", err.Error())
		return err
	}
	log.Printf("Found %d warnings", len(report.Vulnerabilities))

	reports.ResumeReport(r)

	util.CheckSecurityScore(security, int(report.AndroidInfo.SecurityScore))

	return nil
}
