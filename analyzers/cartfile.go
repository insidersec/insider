package analyzers

import (
	"regexp"

	"github.com/insidersec/insider/lexer"
	"github.com/insidersec/insider/models"
	"github.com/insidersec/insider/visitor"
)

var extractLibraryFromCartfile *regexp.Regexp
var cartfileResolverFilter *regexp.Regexp
var cartfileFilter *regexp.Regexp

func init() {
	// Extract the library name, versin and location from the Cartfile.
	extractLibraryFromCartfile = regexp.MustCompile(`(git|github|binary)\s['"](?P<name>[a-zA-Z0-9\/\:\.\-]*)['"]\s(?:(?:~>\s|==\s|>=\s|<=\s|")(?P<version>\d+\.\d+\.\d+|\d+\.\d+)|\"(?P<branch>[a-zA-Z]+)\"|)`)
	cartfileResolverFilter = regexp.MustCompile(`Cartfile.resolved`)
	cartfileFilter = regexp.MustCompile(`(?i)cartfile`)
}

func ExtractLibsFromCartfile(file lexer.InputFile) (libraries []models.Library, err error) {
	findings, err := ExtractLibsFromFile(file.Content, extractLibraryFromCartfile)

	if err != nil {
		return libraries, err
	}

	for _, finding := range findings {
		library := models.Library{
			Name:   finding[2],
			Source: finding[1],
		}

		if finding[3] != "" {
			library.Version = finding[3]
		} else if finding[4] != "" {
			library.Version = finding[4]
		} else {
			library.Version = "latest"
		}

		libraries = append(libraries, library)
	}

	return
}

func isCartfile(filename string) bool {
	if cartfileFilter.MatchString(filename) {
		return true
	}

	return false
}

func isCartfileResolved(filename string) bool {
	if cartfileResolverFilter.MatchString(filename) {
		return true
	}

	return false
}

func ExtractLibsFromCartfiles(dirname string) (libraries []models.Library, err error) {
	files, err := visitor.FindFiles(dirname, false, isCartfileResolved)

	if err != nil {
		return libraries, err
	}

	if len(files) <= 0 {
		// If we do not find a Cartfile.resolved, use the Cartfile instead
		files, err = visitor.FindFiles(dirname, false, isCartfile)

		if err != nil {
			return libraries, err
		}
	}

	for _, file := range files {
		findings, err := ExtractLibsFromCartfile(file)

		if err != nil {
			return libraries, err
		}

		libraries = append(libraries, findings...)
	}

	return
}
