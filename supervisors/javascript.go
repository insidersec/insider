package supervisors

import (
	"encoding/json"
	"insider/export"
	analyzers "insider/lib"
	"insider/models/reports"
	"insider/util"
	"log"
)

// RunJSSourceCodeAnalysis analyzes the given folder and constructs a models.Report.
func RunJSSourceCodeAnalysis(codeInfo SourceCodeInfo, lang string, destinationFolder string, noJSON bool, noHTML bool, security int, verbose bool, ignoreWarnings bool) error {
	log.Println("Starting JavaScript source code analysis")

	report := reports.Report{}

	report.Info.MD5 = codeInfo.MD5Hash
	report.Info.SHA1 = codeInfo.SHA1Hash
	report.Info.SHA256 = codeInfo.SHA256Hash

	if err := analyzers.AnalyzeJSDependencies(destinationFolder, codeInfo.SastID, &report); err != nil {
		return err
	}

	if err := analyzers.AnalyzeNonAppSource(destinationFolder, codeInfo.SastID, "javascript", &report, lang); err != nil {
		return err
	}

	log.Println("Finished JavaScript source code analysis")

	r := reports.DoHtmlReport(report)
	if verbose {
		reports.ConsoleReport(r)
	}

	bReport, err := json.Marshal(report)
	if err != nil {
		return err
	}

	if noJSON {
		log.Println("No Json report")
	} else {
		if err := reportResult(bReport, ignoreWarnings); err != nil {
			return err
		}
	}

	log.Printf("Found %d warnings", len(report.Vulnerabilities))
	if noHTML {
		log.Println("No Html report")
	} else {
		if err := export.ToHtml(r, lang, ignoreWarnings); err != nil {
			return err
		}
	}

	reports.ResumeReport(r)

	util.CheckSecurityScore(security, int(report.Info.SecurityScore))

	return nil
}
