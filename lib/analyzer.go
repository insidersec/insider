package lib

import (
	"fmt"
	"io/ioutil"
	"log"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/insidersec/insider/analyzers"
	"github.com/insidersec/insider/lexer"
	"github.com/insidersec/insider/models"
	"github.com/insidersec/insider/models/reports"
	"github.com/insidersec/insider/visitor"
)

var urlExtractor *regexp.Regexp
var emailExtractor *regexp.Regexp
var commomURLFilter *regexp.Regexp
var commomEmailFilter *regexp.Regexp

func init() {
	commomEmailFilter = regexp.MustCompile(`.*\.png`)
	commomURLFilter = regexp.MustCompile(`(apple|google|android|microsoft)\.com`)

	urlExtractor = regexp.MustCompile(`((?:http|https)://(?:[\w_-]+(?:(?:\.[\w_-]+)+))(?:[\w.,@?^=%&:/~+#-]*[\w@?^=%&/~+#-])?)`)
	emailExtractor = regexp.MustCompile(`(?:[a-z0-9!#$%&'*+/=?^_\x60{|}~\-\.])+@[a-z0-9]+(?:\.[a-z]{2,})+`)
}

func formatClassInfo(filename string, line, column int) string {
	return fmt.Sprintf("%s (%s:%s)", filename, strconv.FormatInt(int64(line), 10), strconv.FormatInt(int64(column), 10))
}

// ConvertFindingToReport converts our internal data object for representing
// a weakness found in the source code being analyzed to the Vulnerability model
// to make a single reporting framework for all analysis
func ConvertFindingToReport(filename, displayName string, finding analyzers.Finding) (vulnerability reports.Vulnerability) {
	formattedClassDisplay := formatClassInfo(
		displayName,
		finding.Line,
		finding.Column,
	)

	formattedClass := formatClassInfo(
		filename,
		finding.Line,
		finding.Column,
	)

	vulnerability = reports.Vulnerability{
		VulnerabilityID: finding.VulnerabilityID,
		// General info
		Line:         finding.Line,
		Class:        formattedClass,
		Method:       finding.Sample,
		Column:       finding.Column,
		CWE:          finding.Info.CWE,
		CVSS:         finding.Info.CVSS,
		ClassMessage: formattedClassDisplay,
		Rank:         finding.Info.Severity,
		LongMessage:  finding.Info.Description,
		ShortMessage: finding.Info.Recomendation,
	}

	return
}

// ConvertAdvisoryToReport do the trick to add the Advisory response from the NPM API
// to the standard reports.LibraryVulnerability struct
func ConvertAdvisoryToReport(advisory models.Advisory) (vulnerability reports.LibraryVulnerability) {
	var title string
	if advisory.Title == "" {
		title = fmt.Sprintf("Vulnerability - %s", advisory.ModuleName)
	} else {
		title = fmt.Sprintf("%s - %s", advisory.Title, advisory.ModuleName)
	}

	vulnerability = reports.LibraryVulnerability{
		Title:         title,
		ID:            advisory.ID,
		CWE:           advisory.CWE,
		CVEs:          strings.Join(advisory.CVEs, " "),
		Severity:      advisory.Severity,
		Description:   advisory.Overview,
		Recomendation: advisory.Recomendation,
	}

	return
}

// LoadsFilesAndRules loads up a given directory following the visitor rules for
// the language being analyzed, so we can speed up analysis time by removing useless files
// and also loads the rules for the given language.
// The returned errors should be handled by the caller.
func LoadsFilesAndRules(dirname, tech string, lang string) (files []string, loadedRules []lexer.Rule, err error) {
	files, err = visitor.LoadSourceDir(dirname, tech)

	if err != nil {
		return
	}

	log.Printf("Found %d files to analyze.", len(files))

	loadedRules, err = lexer.LoadRules(tech, lang)

	// Since even if there is an error we have to return it,
	// and we are using named parameters, we can safely return now.
	return
}

// CalculateSecurityScore holds the logic to cauculate the Security Score for the
// whole report
func CalculateSecurityScore(highestCVSS float64) float32 {
	return float32(100 - int(highestCVSS*10))
}

// AnalyzeNonAppSource is a special function that will handle
// the sample to be analyzed as a simple generic source code
// since it do not need any special threatment.
func AnalyzeNonAppSource(dirname, sastID, tech string, report *reports.Report, lang string) error {
	files, rules, err := LoadsFilesAndRules(dirname, tech, lang)

	if err != nil {
		return err
	}

	appSize, err := analyzers.GetUnpackedAppSize(dirname)

	if err != nil {
		return err
	}

	report.Info.Size = fmt.Sprintf("%s Bytes", strconv.Itoa(appSize))

	log.Println("Starting extracting hardcoded information")

	// err = ExtractHardcodedInfo(dirname, sastID, report)

	// if err != nil {
	// 	return err
	// }

	log.Println("Finished hardcoded information extraction")

	highestCVSS := 0.0

	report.SetSastID(sastID)

	log.Println("Staring main code analysis")
	for _, file := range files {
		fileContent, err := ioutil.ReadFile(file)

		if err != nil {
			return err
		}

		fileForAnalyze, err := visitor.NewInputFile(dirname, file, fileContent)
		if err != nil {
			return err
		}

		report.Info.NumberOfLines = report.Info.NumberOfLines + len(fileForAnalyze.NewlineIndexes)

		urls := extractURLs(report.GetDRAURLs(), fileForAnalyze.Content)
		emails := extractEmails(report.GetDRAEmails(), fileForAnalyze.Content)

		report.AddDRAURLs(urls, fileForAnalyze.PhysicalPath)
		report.AddDRAEmails(emails, fileForAnalyze.PhysicalPath)
		// cleaning DRA url
		for item, _ := range report.DRA {
			newstring := strings.Split(report.DRA[item].FilePath, "/tmp/")
			if len(newstring) > 1 {
				tempstring := newstring[1]
				i := strings.Index(tempstring, "/")
				report.DRA[item].FilePath = tempstring[i:]
			}
		}

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

			vulnerability.SastID = sastID

			if vulnerability.CVSS > highestCVSS {
				highestCVSS = vulnerability.CVSS
			}

			report.Vulnerabilities = append(report.Vulnerabilities, vulnerability)
		}
	}

	log.Println("Finished main code analysis")

	report.Info.AverageCVSS = highestCVSS
	report.Info.SecurityScore = CalculateSecurityScore(report.Info.AverageCVSS)
	report.Info.SastID = sastID

	report.SanitizeDRA()

	log.Printf("Scanned %d lines", report.Info.NumberOfLines)

	return nil
}

//##################### DATA EXTRACTION ##################################

// DRAReport represents a DRA complied Report struct
type DRAReport interface {
	SetSastID(sastID string)

	AddDRAURLs(urls []string, filepath string)
	AddDRAEmails(emails []string, filepath string)

	GetDRAURLs() []string
	GetDRAEmails() []string
}

func findFilesForDataExtraction(filename string) bool {
	// Excludes general common files such as .png files
	if visitor.ExtensionFilter.MatchString(filename) {
		return false
	}

	if strings.Contains(filename, "package-lock.json") {
		return false
	}

	return true
}

// isUnique grants that the record is not in the given slice
// WARNING: The slice MUST BE SORTED
// For example with sort.Strings function
func isUnique(records []string, record string) bool {
	index := sort.SearchStrings(records, record)

	return !(index < len(records) && records[index] == record)
}

func extractURLs(records []string, content string) (result []string) {
	//log.Println(content)
	urls := urlExtractor.FindAllStringSubmatch(content, -1)

	for _, rawURLs := range urls {

		for _, rawURL := range rawURLs {
			if !commomURLFilter.MatchString(rawURL) {
				sort.Strings(records)

				if len(records) == 0 || isUnique(records, rawURL) {
					result = append(result, rawURL)
				}
			}

		}
	}

	return
}

func extractEmails(records []string, content string) (result []string) {
	emails := emailExtractor.FindAllStringSubmatch(content, -1)

	for _, rawEmails := range emails {
		for _, rawEmail := range rawEmails {

			if !commomEmailFilter.MatchString(rawEmail) {
				sort.Strings(records)

				if len(records) == 0 || isUnique(records, rawEmail) {
					result = append(result, rawEmail)
				}
			}
		}
	}

	return
}

// ExtractHardcodedInfo goes after information left
// hardcoded inside the app, to be able to enumerate
// and exposes the number and the quality of information
// gathered regardless any bug in the application.
func ExtractHardcodedInfo(dirname, sastID string, report DRAReport) (err error) {
	files, err := visitor.FindFiles(dirname, false, findFilesForDataExtraction)

	if err != nil {
		return err
	}

	report.SetSastID(sastID)

	// Extract all the URLs for each of the files found
	for _, file := range files {
		urls := extractURLs(report.GetDRAURLs(), file.Content)
		emails := extractEmails(report.GetDRAEmails(), file.Content)

		report.AddDRAURLs(urls, file.PhysicalPath)
		report.AddDRAEmails(emails, file.PhysicalPath)
	}

	return nil
}
