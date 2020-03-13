package supervisors

import (
	"bytes"
	"encoding/json"
	"html/template"
	"log"
	"os"
	"path/filepath"

	"github.com/insidersec/insider/models"
)

// ResultFolderName is the default output folder for reports
const ResultFolderName string = "results"
const resultJSONFilename string = "report.json"
const resultHTMLFilename string = "report.html"

// SourceCodeInfo holds information about the received code to analyze
type SourceCodeInfo struct {
	Tech             string
	PhysicalPath     string
	ForceOverwriting bool
}

type templateData struct {
	Count           int
	Vulnerabilities []models.Vulnerability
}

func exportHTMLReport(findings []models.Vulnerability) error {
	reportHTML := filepath.Join(ResultFolderName, resultHTMLFilename)

	htmlFile, err := os.OpenFile(reportHTML, os.O_CREATE|os.O_WRONLY, 0600)

	if err != nil {
		return err
	}

	defer htmlFile.Close()

	// Makes sure we start to write in the beginning of the file
	// and overwriting anything that was previously inside the file
	err = htmlFile.Truncate(0)

	if err != nil {
		log.Println("Problems writing the report to the HTML file.")
		return err
	}

	_, err = htmlFile.Seek(0, 0)

	if err != nil {
		log.Println("Problems writing the report to the HTML file.")
		return err
	}

	rawTemplate := getReportHTML()
	reportTemplate, err := template.New("report").Parse(rawTemplate)

	if err != nil {
		return err
	}

	templateData := templateData{
		Count:           len(findings),
		Vulnerabilities: findings,
	}

	err = reportTemplate.Execute(htmlFile, templateData)

	if err != nil {
		return err
	}

	log.Println("Saved report's HTML")

	return nil
}

func exportJSONReport(bReport []byte) error {
	reportJSON := filepath.Join(ResultFolderName, resultJSONFilename)

	jsonFile, err := os.OpenFile(reportJSON, os.O_CREATE|os.O_WRONLY, 0600)

	if err != nil {
		log.Println("Problems writing the report to the JSON file.")
		return err
	}

	defer jsonFile.Close()

	// Makes sure we start to write in the beginning of the file
	// and overwriting anything that was previously inside the file
	err = jsonFile.Truncate(0)

	if err != nil {
		log.Println("Problems writing the report to the JSON file.")
		return err
	}

	_, err = jsonFile.Seek(0, 0)

	if err != nil {
		log.Println("Problems writing the report to the JSON file.")
		return err
	}

	var outputBuffer bytes.Buffer

	// This will format the output according to the
	// JSON specification to be easier to read by a human

	// - the first parameter is a pointer to the output buffer
	// - the second one is the actual byte slice with the data
	// - the third is a prefix to each line in the input buffer
	// - the fourth is the actual character to be used in identation
	//    here we're using space for compatibility
	if err := json.Indent(&outputBuffer, bReport, "", " "); err != nil {
		log.Println("Problems writing the report to the JSON file.")
		return err
	}

	bytesWritten, err := jsonFile.Write(outputBuffer.Bytes())

	if err != nil {
		log.Println("Problems writing the report to the JSON file.")
		return err
	}

	log.Printf("Saved report's JSON with %f MB", float64(bytesWritten)/(1024*1024))
	return nil
}

// reportResult will handle the logic to upload the final report about the source code
// being analyzed to somewhere it can be feed into other tools or used by hand.
// By default, in development environment it will save the report to a file in the
// current directory with the name of report.json
func reportResult(codeInfo SourceCodeInfo, findings []models.Vulnerability, bReport []byte) error {
	log.Println("Writting report...")

	err := exportJSONReport(bReport)

	if err != nil {
		return err
	}

	err = exportHTMLReport(findings)

	if err != nil {
		return err
	}

	return nil
}
