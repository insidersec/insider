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
func RunJSSourceCodeAnalysis(codeInfo SourceCodeInfo, lang string, destinationFolder string, noJSON bool, noHTML bool, security int, verbose bool) error {
	log.Println("Starting JavaScript source code analysis")

	report := reports.Report{}

	report.Info.MD5 = codeInfo.MD5Hash
	report.Info.SHA1 = codeInfo.SHA1Hash
	report.Info.SHA256 = codeInfo.SHA256Hash

	err := analyzers.AnalyzeJSDependencies(destinationFolder, codeInfo.SastID, &report)

	if err != nil {
		log.Println(err.Error())
		return err
	}

	err = analyzers.AnalyzeNonAppSource(destinationFolder, codeInfo.SastID, "javascript", &report, lang)

	if err != nil {
		log.Println(err.Error())
		return err
	}

	log.Println("Finished JavaScript source code analysis")

	r := reports.DoHtmlReport(report)
	if verbose {
		reports.ConsoleReport(r)
	}

	bReport, err := json.Marshal(report)

	if err != nil {
		log.Println(err.Error())
		return err
	}
	if noJSON {
		log.Println("No Json report")
	} else {
		err = reportResult(codeInfo, bReport)
		if err != nil {
			return err
		}
	}

	log.Printf("Found %d warnings", len(report.Vulnerabilities))
	if noHTML {
		log.Println("No Html report")
	} else {
		export.ToHtml(r, lang)
	}

	reports.ResumeReport(r)

	util.CheckSecurityScore(security, int(report.Info.SecurityScore))

	return nil
}
