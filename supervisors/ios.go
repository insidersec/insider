package supervisors

import (
	"encoding/json"
	"insider/export"
	"insider/util"
	"insider/visitor"
	"log"

	analyzers "insider/lib"
	"insider/models/reports"
)

// RunIOSCodeAnalysis self-explained
func RunIOSCodeAnalysis(codeInfo SourceCodeInfo, lang string, destinationFolder string, noJSON bool, noHTML bool, security int, verbose bool, ignoreWarnings bool) error {
	log.Println("Starting iOS Source code analysis")

	report := reports.IOSReport{}

	report.IOSInfo.MD5 = codeInfo.MD5Hash
	report.IOSInfo.SHA1 = codeInfo.SHA1Hash
	report.IOSInfo.SHA256 = codeInfo.SHA256Hash

	iosType, err := visitor.ClassifySample(destinationFolder)
	if err != nil {
		return err
	}

	switch iosType {
	case "source":
		log.Println("Extracting libraries")
		libraries, err := analyzers.ExtractLibrariesFromFiles(destinationFolder, codeInfo.SastID)
		if err != nil {
			return err
		}

		report.Libraries = libraries

		if err := analyzers.AnalyzeIOSSource(destinationFolder, codeInfo.SastID, &report, lang); err != nil {
			return err
		}
	case "binary":
		if err := analyzers.AnalyzeIOSBinary(destinationFolder, codeInfo.SastID, &report, lang); err != nil {
			return err
		}
	}

	log.Println("Finished code analysis")

	bReport, err := json.Marshal(report)
	if err != nil {
		return err
	}

	r := reports.DoHtmlReport(report)
	if verbose {
		reports.ConsoleReport(r)
	}

	if noJSON {
		log.Println("No Json report")
	} else {
		if err := reportResult(bReport, ignoreWarnings); err != nil {
			return err
		}
	}

	if noHTML {
		log.Println("No Html report")
	} else {
		if err := export.ToHtml(r, lang, ignoreWarnings); err != nil {
			return err
		}
	}

	log.Printf("Found %d warnings", len(report.Vulnerabilities))

	reports.ResumeReport(r)

	util.CheckSecurityScore(security, int(report.IOSInfo.SecurityScore))

	return nil
}
