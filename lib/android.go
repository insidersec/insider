package lib

import (
	"fmt"
	"insider/analyzers"
	"insider/models/reports"
	"insider/visitor"
	"io/ioutil"
	"log"
	"strconv"
)

/*
**************************************************
*                Public Functions                *
**************************************************
 */

// AnalyzeAndroidManifest self-explained
func AnalyzeAndroidManifest(dirname, sastID string, report *reports.AndroidReport, lang string) error {
	return analyzers.AnalyzeAndroidManifest(dirname, sastID, report, lang)
}

// AnalyzeAndroidSource self-explained
func AnalyzeAndroidSource(dirname, sastID string, report *reports.AndroidReport, lang string) error {
	files, rules, err := LoadsFilesAndRules(dirname, "android", lang)

	if err != nil {
		return err
	}

	appSize, err := analyzers.GetUnpackedAppSize(dirname)

	if err != nil {
		return err
	}

	report.AndroidInfo.Size = fmt.Sprintf("%s MB", strconv.Itoa(appSize))

	log.Println("Starting extracting hardcoded information")

	err = ExtractHardcodedInfo(dirname, sastID, report)

	if err != nil {
		return err
	}

	log.Println("Finished hardcoded information extraction")

	log.Println("Starting main source code analysis")

	highestCVSS := 0.0

	for _, file := range files {
		//log.Println("Code analysis", file)
		fileContent, err := ioutil.ReadFile(file)

		if err != nil {
			return err
		}

		fileForAnalyze, err := visitor.NewInputFile(dirname, file, fileContent)
		if err != nil {
			return err
		}

		report.AndroidInfo.NumberOfLines = report.AndroidInfo.NumberOfLines + len(fileForAnalyze.NewlineIndexes)

		urls := extractURLs(report.GetDRAURLs(), fileForAnalyze.Content)
		emails := extractEmails(report.GetDRAEmails(), fileForAnalyze.Content)

		report.AddDRAURLs(urls, fileForAnalyze.PhysicalPath)
		report.AddDRAEmails(emails, fileForAnalyze.PhysicalPath)

		fileSummary := analyzers.AnalyzeFile(fileForAnalyze, rules)

		for _, finding := range fileSummary.Findings {
			vulnerability := ConvertFindingToReport(
				fileForAnalyze.Name,
				fileForAnalyze.DisplayName,
				finding,
			)

			// Now we search other files affected by this vulnerability
			for _, affectedFile := range files {
				affectedFileContent, err := ioutil.ReadFile(affectedFile)

				if err != nil {
					return err
				}

				affectedInputFile, err := visitor.NewInputFile(dirname, affectedFile, affectedFileContent)
				if err != nil {
					return err
				}

				if affectedInputFile.Uses(fileForAnalyze.ImportReference) {
					vulnerability.AffectedFiles = append(vulnerability.AffectedFiles, affectedInputFile.DisplayName)
				}
			}

			if vulnerability.CVSS > highestCVSS {
				highestCVSS = vulnerability.CVSS
			}

			vulnerability.SastID = sastID

			report.Vulnerabilities = append(report.Vulnerabilities, vulnerability)
		}
	}

	report.AndroidInfo.HighestCVSS = highestCVSS
	report.AndroidInfo.SecurityScore = CalculateSecurityScore(report.AndroidInfo.HighestCVSS)
	report.AndroidInfo.SastID = sastID

	log.Println("Finished main source code analysis")
	log.Printf("Scanned %d lines", report.AndroidInfo.NumberOfLines)

	return nil
}
