package lib

import (
	"fmt"
	"io/ioutil"
	"log"
	"strconv"

	"github.com/insidersec/insider/analyzers"
	"github.com/insidersec/insider/lexer"
	"github.com/insidersec/insider/models"
)

// AnalyzeIOSSource self-explained
func AnalyzeIOSSource(dirname string, report *models.IOSReport) error {
	files, rules, err := LoadsFilesAndRules(dirname, "ios")

	if err != nil {
		return err
	}

	appSize, err := analyzers.GetUnpackedAppSize(dirname)

	if err != nil {
		return err
	}

	report.IOSInfo.Size = fmt.Sprintf("%s MB", strconv.Itoa(appSize))

	for _, file := range files {
		fileContent, err := ioutil.ReadFile(file)

		if err != nil {
			return err
		}

		fileForAnalyze := lexer.NewInputFile(dirname, file, fileContent)

		fileForAnalyze.Libraries = report.Libraries
		report.IOSInfo.NumberOfLines = report.IOSInfo.NumberOfLines + len(fileForAnalyze.NewlineIndexes)

		fileSummary := analyzers.AnalyzeFile(fileForAnalyze, rules)

		for _, finding := range fileSummary.Findings {
			vulnerability := ConvertFindingToReport(
				fileForAnalyze.Name,
				fileForAnalyze.DisplayName,
				finding,
			)

			report.Vulnerabilities = append(report.Vulnerabilities, vulnerability)
		}
	}

	log.Printf("Scanned %d lines", report.IOSInfo.NumberOfLines)

	return nil
}

// ExtractLibrariesFromFiles self-explained
func ExtractLibrariesFromFiles(dirname string) (libraries []models.Library, err error) {
	podfileLibraries, err := analyzers.ExtractLibsFromPodfiles(dirname)

	if err != nil {
		return libraries, err
	}

	for _, library := range podfileLibraries {
		libraries = append(libraries, library)
	}

	cartfileLibraries, err := analyzers.ExtractLibsFromCartfiles(dirname)

	if err != nil {
		return libraries, err
	}

	for _, library := range cartfileLibraries {
		libraries = append(libraries, library)
	}

	return
}
