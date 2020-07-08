package lib

import (
	"encoding/json"
	"log"
	"regexp"

	"insider/connectors"
	"insider/models"
	"insider/models/reports"
	"insider/visitor"
)

const (
	// PackageFilename is the default package.json filename
	PackageFilename string = "package.json"
)

var packageJSONFinder *regexp.Regexp

func init() {
	packageJSONFinder = regexp.MustCompile(`package\.json`)
}

func findPackageJSON(filename string) bool {
	return packageJSONFinder.MatchString(filename)
}

func getPackageJSON(dirname string) (packageJSON models.PackageJSON, err error) {
	packageFiles, err := visitor.FindFiles(dirname, false, findPackageJSON)

	if err != nil {
		return
	}

	var rootPackageFile visitor.InputFile
	for _, packageFile := range packageFiles {
		if rootPackageFile.PhysicalPath != "" {
			if len(rootPackageFile.PhysicalPath) > len(packageFile.PhysicalPath) {
				rootPackageFile.PhysicalPath = packageFile.PhysicalPath
				rootPackageFile.Content = packageFile.Content
			}
		} else {
			rootPackageFile.PhysicalPath = packageFile.PhysicalPath
			rootPackageFile.Content = packageFile.Content
		}
	}

	log.Printf("Found package.json file at %s", rootPackageFile.PhysicalPath)

	err = json.Unmarshal([]byte(rootPackageFile.Content), &packageJSON)

	if err != nil {
		return
	}

	return
}

// AnalyzeJSDependencies uses data from package.json
// file to search in the NPM Advisory API for known
// vulnerabilities in the packages that are in use
// by the application.
func AnalyzeJSDependencies(dirname, sastID string, report *reports.Report) error {
	libraries := []reports.Library{}
	packageJSON, err := getPackageJSON(dirname)
	existpackageJSON := true

	if err != nil {
		log.Println("Package.json not found but the process goes on")
		existpackageJSON = false
	}

	for dependency, version := range packageJSON.Dependencies {
		libraryFound := reports.Library{
			SastID:  sastID,
			Version: version,
			Name:    dependency,
		}

		libraries = append(libraries, libraryFound)
	}

	if len(libraries) <= 0 && existpackageJSON == true {
		log.Println("Didn't found any library in package.json file, something should have gone wrong.")
	}

	report.Libraries = libraries

	report.Info.Name = packageJSON.Name
	report.Info.Version = packageJSON.Version

	auditResult, err := connectors.AuditLibraries(packageJSON)

	if err != nil {
		return err
	}

	for _, libraryAdvisory := range auditResult.Advisories {
		libraryIssue := ConvertAdvisoryToReport(libraryAdvisory)

		libraryIssue.SastID = sastID

		report.LibraryIssues = append(report.LibraryIssues, libraryIssue)
	}

	return nil
}
