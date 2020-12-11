package supervisors

import (
	"encoding/json"
	"github.com/insidersec/insider/export"
	"github.com/insidersec/insider/util"
	"log"

	analyzers "github.com/insidersec/insider/lib"
	"github.com/insidersec/insider/models/reports"
)

// RunCSharpSourceCodeAnalysis analyzes the given folder and constructs a models.Report.
func RunCSharpSourceCodeAnalysis(codeInfo SourceCodeInfo, lang string, destinationFolder string, noJSON bool, noHTML bool, security int, verbose bool, ignoreWarnings bool) error {
	log.Println("Starting C# source code analysis")

	report := reports.Report{}

	report.Info.MD5 = codeInfo.MD5Hash
	report.Info.SHA1 = codeInfo.SHA1Hash
	report.Info.SHA256 = codeInfo.SHA256Hash

	if err := analyzers.AnalyzeNonAppSource(destinationFolder, codeInfo.SastID, "csharp", &report, lang); err != nil {
		return err
	}

	log.Println("Finished C# source code analysis")

	bReport, err := json.Marshal(report)
	if err != nil {
		return err
	}

	r := reports.DoHtmlReport(report)
	reports.ConsoleReport(r)

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

	util.CheckSecurityScore(security, int(report.Info.SecurityScore))

	return nil
}
