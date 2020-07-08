package analyzers

import (
	"regexp"
	"strings"

	"insider/models/reports"
	"insider/visitor"
)

var extractLibraryFromPodfile *regexp.Regexp
var podfileFilter *regexp.Regexp

func init() {
	extractLibraryFromPodfile = regexp.MustCompile(`pod\s'(?P<name>[[:alnum:]]+)'(?:,\s'(?:~>|>=|<=|)(?P<version>\d\.\d\.\d|\s\d\.\d\.\d|\s\d\.\d)|)`)
	podfileFilter = regexp.MustCompile(`(?i)(?:\.Podfile|Podfile)`)
}

// ExtractLibsFromPodfile selfexplained
func ExtractLibsFromPodfile(file visitor.InputFile) (libraries []reports.Library, err error) {
	findings, err := ExtractLibsFromFile(file.Content, extractLibraryFromPodfile)

	if err != nil {
		return libraries, err
	}

	for _, finding := range findings {
		library := reports.Library{
			Name:   finding[1],
			Source: "CocoaPod",
		}

		if finding[2] != "" {
			library.Version = strings.TrimSpace(finding[2])
		} else {
			library.Version = "latest"
		}

		libraries = append(libraries, library)
	}

	return
}

func isPodfile(filename string) bool {
	return podfileFilter.MatchString(filename)
}

// ExtractLibsFromPodfiles selfexplained
func ExtractLibsFromPodfiles(dirname string) (libraries []reports.Library, err error) {
	files, err := visitor.FindFiles(dirname, false, isPodfile)

	if err != nil {
		return libraries, err
	}

	for _, file := range files {
		findings, err := ExtractLibsFromPodfile(file)

		if err != nil {
			return libraries, err
		}

		libraries = append(libraries, findings...)
	}

	return
}
