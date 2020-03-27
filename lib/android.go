package lib

import (
	"fmt"
	"log"
	"strconv"
	"io/ioutil"
	"path/filepath"
	"github.com/insidersec/insider/analyzers"
	"github.com/insidersec/insider/lexer"
	"github.com/insidersec/insider/models"
)

/*
**************************************************
*                Public Functions                *
**************************************************
 */

func AnalyzeAndroidManifest(dirname string, report *models.AndroidReport) error {
	return analyzers.AnalyzeAndroidManifest(dirname, report)
}

func AnalyzeAndroidSource(dirname string, report *models.AndroidReport) error {
	files, rules, err := LoadsFilesAndRules(dirname, "android")

	if err != nil {
		return err
	}

	appSize, err := analyzers.GetUnpackedAppSize(dirname)

	if err != nil {
		return err
	}

	report.AndroidInfo.Size = fmt.Sprintf("%s MB", strconv.Itoa(appSize))

	for _, file := range files {
		fileContent, err := ioutil.ReadFile(filepath.Clean(file))

		if err != nil {
			return err
		}

		fileForAnalyze := lexer.NewInputFile(dirname, file, fileContent)

		report.AndroidInfo.NumberOfLines = report.AndroidInfo.NumberOfLines + len(fileForAnalyze.NewlineIndexes)

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

	log.Printf("Scanned %d lines", report.AndroidInfo.NumberOfLines)

	return nil
}
