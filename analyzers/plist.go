package analyzers

import (
	"regexp"
	"strings"

	"insider/models/reports"
	"insider/visitor"
)

var extractBundleID *regexp.Regexp
var plistFilesFilter *regexp.Regexp
var informativeFilesFilter *regexp.Regexp

func init() {
	extractBundleID = regexp.MustCompile(`<key>BUNDLE_ID</key>(?:\n*.*)<string>(.*)</string>`)

	plistFilesFilter = regexp.MustCompile(`.plist`)
	informativeFilesFilter = regexp.MustCompile(`.xcodeproj|.plist`)
}

func findInfoFiles(path string) bool {
	return informativeFilesFilter.MatchString(path)
}

func findPListFiles(path string) bool {
	return plistFilesFilter.MatchString(path)
}

// AnalyzePList self-explained
func AnalyzePList(dirname string, report *reports.IOSReport) error {
	files, err := visitor.FindFiles(dirname, true, findInfoFiles)

	if err != nil {
		return err
	}

	var actualAppDir visitor.InputFile

	for _, infoFileDir := range files {
		if infoFileDir.IsDir {
			if strings.Contains(infoFileDir.Name, ".xcodeproj") {
				if actualAppDir.PhysicalPath == "" {
					actualAppDir = infoFileDir
					continue
				} else if len(actualAppDir.PhysicalPath) > len(infoFileDir.PhysicalPath) {
					actualAppDir = infoFileDir
				}
			}
		}
	}

	report.IOSInfo.AppName = strings.Split(actualAppDir.Name, ".xcodeproj")[0]

	mainAppDir := strings.Split(actualAppDir.PhysicalPath, ".xcodeproj")[0]

	mainAppFiles, err := visitor.FindFiles(mainAppDir, false, findPListFiles)

	if err != nil {
		return err
	}

	for _, mainAppFile := range mainAppFiles {
		results := extractBundleID.FindStringSubmatch(mainAppFile.Content)

		if results != nil {
			report.IOSInfo.BinaryID = results[1]
		}
	}

	return nil
}
