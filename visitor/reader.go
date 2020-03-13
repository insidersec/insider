package visitor

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/insidersec/insider/lexer"
)

var iosExtraFilter *regexp.Regexp
var extensionFilter *regexp.Regexp
var jsExtensionFilter *regexp.Regexp
var iosExtensionFilter *regexp.Regexp
var csharpExtensionFilter *regexp.Regexp
var androidExtensionFilter *regexp.Regexp

func init() {
	extensionFilter = regexp.MustCompile(`(\w*\.[ot]tf)|(\w*\.bat)|(\w*\.sh)|(\w*\.png)|(\w*\.jpg)|(\w*\.jpeg)|(\w*\.pdf)|(\w*\.md)|(\w*\.markdown)|(\w*\.svg)|(\w*\.woff2)|(\w*\.woff)|(\w*\.ico)|(\w*LICENSE)|(\w*\.txt)|(\w*\.eot)|(\w*\.git)`)

	androidExtensionFilter =
		regexp.MustCompile(`(\s*gradle\/.+\.jar)|(\w+\/android\/\w+)|(.+\.aar)|(.+\.cpp)|(.+\.h)|(.+\.mk)|(.+\.c)|(.+\.dex)|(.+\.apk)`)
	iosExtensionFilter =
		regexp.MustCompile(`(\w*\.swift)|(\w*\.h)|\w*\.m+`)
	// Useless files in iOS .IPA files
	iosExtraFilter = regexp.MustCompile(`(?i)(\w+\/Build\/\w+)|(\w+\/docs/\w+)|(\w+\/\w*[tT]est\w*\/\w+)|(\w*\.aep)|(\w+\/Assets\w*\/\w+)|(\w+\/\w*idwall.*\/\w+)|(\w*\.xcscheme)|(\w*\.pbxproj)|(\w*\.storyboard)|(\w*\.\w*proj)|(\w*\.plist)|(\w*\.modulemap)|(\w+\/\w+.framework\/\w+)|(.+\.ipa)`)

	csharpExtensionFilter = regexp.MustCompile(`(.+\.css)|(.+\.map)|(.+\.js)|(.+\.exe)|(.+\.dll)|(.+\.p12)|(.+\.xml)|(.+\.svcmap)|(.+\.svcinfo)|(.+\.disco)`)

	jsExtensionFilter = regexp.MustCompile(`(.+\.js)|(.+\.jsx)|(.+\.ts)|(.+\.tsx)|`)
}

func androidManifestFilter(filename string) bool {
	androidManifestExpression := regexp.MustCompile(`(AndroidManifest\.xml)|(strings\.xml)`)
	otherXMLExpression := regexp.MustCompile(`\w*.xml`)

	return !androidManifestExpression.MatchString(filename) &&
		otherXMLExpression.MatchString(filename)
}

/*
********************************************
*    Public functions                      *
********************************************
 */

// FindFunc should be used with FindFiles to
// match certain criteria inside a folder
type FindFunc func(dirname string) bool

// FindFiles searches for filenames who the given FindFunc returns true
func FindFiles(dirname string, includeDirs bool, isFile FindFunc) ([]lexer.InputFile, error) {
	files := make([]lexer.InputFile, 0)
	err := filepath.Walk(dirname, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Ignore __MACOSX files since it's generally metadata
		if strings.Contains(path, "__MACOSX") {
			return nil
		}

		if isFile(path) {
			if info.IsDir() {
				if includeDirs {
					file := lexer.NewInputFile(dirname, path, []byte{})

					file.IsDir = true

					files = append(files, file)
					return nil
				}
			}

			fileContent, err := ioutil.ReadFile(path)

			if err != nil {
				return err
			}

			file := lexer.NewInputFile(dirname, path, fileContent)

			files = append(files, file)
			return nil
		}

		return nil
	})

	if err != nil {
		return files, err
	}

	return files, nil
}

// LoadSourceDir returns all the filenames that should be
// analyzed for the given supported technology
// The default rules already include a lot of weird stuff
// such as font files, PDF documents and images.
func LoadSourceDir(dirname, tech string) ([]string, error) {
	files := make([]string, 0)
	err := filepath.Walk(dirname, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		if extensionFilter.MatchString(path) {
			return nil
		}

		switch tech {
		case "android":
			if androidExtensionFilter.MatchString(path) {
				return nil
			}

			if androidManifestFilter(path) {
				files = append(files, path)
				return nil
			}

			files = append(files, path)
		case "ios":
			if iosExtraFilter.MatchString(path) {
				return nil
			}

			if iosExtensionFilter.MatchString(path) {
				files = append(files, path)
				return nil
			}

		case "csharp":
			if csharpExtensionFilter.MatchString(path) {
				return nil
			}

			files = append(files, path)
		case "javascript":
			if jsExtensionFilter.MatchString(path) {
				files = append(files, path)
			}

		default:
			files = append(files, path)
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	return files, nil
}
