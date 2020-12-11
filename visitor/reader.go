package visitor

import (
	"archive/zip"
	"encoding/json"
	"github.com/insidersec/insider/config"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	yaml "gopkg.in/yaml.v3"
)

// ExtensionFilter excludes useless files
var ExtensionFilter *regexp.Regexp

var iosExtraFilter *regexp.Regexp
var jsExtensionFilter *regexp.Regexp
var iosExtensionFilter *regexp.Regexp
var csharpExtensionFilter *regexp.Regexp
var androidExtensionFilter *regexp.Regexp

func init() {
	ExtensionFilter = regexp.MustCompile(`(\w*\.[ot]tf)|(\w*\.bat)|(\w*\.sh)|(\w*\.png)|(\w*\.jpg)|(\w*\.jpeg)|(\w*\.pdf)|(\w*\.md)|(\w*\.markdown)|(\w*\.svg)|(\w*\.woff2)|(\w*\.woff)|(\w*\.ico)|(\w*LICENSE)|(\w*\.txt)|(\w*\.eot)|(\w*\.git\W)|(\w*\.gitignore)`)

	androidExtensionFilter =
		regexp.MustCompile(`(\s*gradle\/.+\.jar)|(\w+\/android\/\w+)|(.+\.aar)|(.+\.cpp)|(.+\.h)|(.+\.mk)|(.+\.c)|(.+\.dex)|(.+\.apk)`)
	iosExtensionFilter =
		regexp.MustCompile(`(\w*\.swift)|(\w*\.h)|\w*\.m+`)
	// Useless files in iOS .IPA files
	iosExtraFilter = regexp.MustCompile(`(?i)(\w+\/Build\/\w+)|(\w+\/docs/\w+)|(\w+\/\w*[tT]est\w*\/\w+)|(\w*\.aep)|(\w+\/Assets\w*\/\w+)|(\w+\/\w*idwall.*\/\w+)|(\w*\.xcscheme)|(\w*\.pbxproj)|(\w*\.storyboard)|(\w*\.\w*proj)|(\w*\.plist)|(\w*\.modulemap)|(\w+\/\w+.framework\/\w+)|(.+\.ipa)`)

	csharpExtensionFilter = regexp.MustCompile(`(.+\.css)|(.+\.map)|(.+\.js)|(.+\.exe)|(.+\.dll)|(.+\.p12)|(.+\.xml)|(.+\.svcmap)|(.+\.svcinfo)|(.+\.disco)|(.+\.cache)`)

	jsExtensionFilter = regexp.MustCompile(`(.+\.js)|(.+\.jsx)|(.+\.ts)|(.+\.tsx)`)
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

// Unzip creates a folder with the given archive file
// name and unzips all its content inside of it.
func Unzip(sourceFile string) (string, error) {
	r, err := zip.OpenReader(sourceFile)

	if err != nil {
		return "", err
	}

	defer r.Close()

	fileExtension := filepath.Ext(sourceFile)
	destinationFolder := sourceFile[0 : len(sourceFile)-len(fileExtension)]

	for _, file := range r.File {
		// Store filename/path for returning and using later on
		filePath := filepath.Join(destinationFolder, file.Name)

		if file.FileInfo().IsDir() {
			// Make Folder
			if err := os.MkdirAll(filePath, os.ModePerm); err != nil {
				return "", err
			}
			continue
		}

		// Make File
		if err = os.MkdirAll(filepath.Dir(filePath), os.ModePerm); err != nil {
			return destinationFolder, err
		}

		outFile, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, file.Mode())
		if err != nil {
			return destinationFolder, err
		}

		rc, err := file.Open()
		if err != nil {
			return destinationFolder, err
		}

		_, err = io.Copy(outFile, rc)

		// Close the file without defer to close before next iteration of loop
		outFile.Close()
		rc.Close()

		if err != nil {
			return destinationFolder, err
		}
	}
	return destinationFolder, nil
}

// FindFunc should be used with FindFiles to
// match certain criteria inside a folder
type FindFunc func(dirname string) bool

// FindFiles searches for filenames who the given FindFunc returns true
func FindFiles(dirname string, includeDirs bool, isFile FindFunc) ([]InputFile, error) {
	files := make([]InputFile, 0)
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
					file, err := NewInputFile(dirname, path, []byte{})
					if err != nil {
						return err
					}

					file.IsDir = true

					files = append(files, file)
					return nil
				}

				return nil
			}

			fileContent, err := ioutil.ReadFile(path)

			if err != nil {
				return err
			}

			file, err := NewInputFile(dirname, path, fileContent)
			if err != nil {
				return err
			}

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

		if ExtensionFilter.MatchString(path) {
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
		case "iac":
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

	//newfiles := make([]string, 0)

	// cleanning the list os files with  filelistcontrol.json
	err = config.CleanListFiles(tech, &files)
	if err != nil {
		return nil, err
	}

	return files, nil
}

// ParseCloudFormationTemplate try to parse the given file
// to fullfill the cloudformation.Template struct
func ParseCloudFormationTemplate(filename string) (template map[string]interface{}, err error) {
	file, err := ioutil.ReadFile(filename)

	if err != nil {
		return
	}

	extension := filepath.Ext(filename)

	// If founds a YAML file uses the right package do unmarshal it.
	if extension == ".yml" || extension == ".yaml" {
		err = yaml.Unmarshal(file, &template)

		if err != nil {
			return
		}

		return
	}

	// Otherwise will use the built-in JSON unmarshaler
	err = json.Unmarshal(file, &template)

	if err != nil {
		// Sometimes the extension is ".template"
		// and as it could be a YAML file
		// Only if is this case we try again
		if extension == ".template" {
			err = yaml.Unmarshal(file, &template)

			if err != nil {
				return
			}
		}

		return
	}

	return
}
