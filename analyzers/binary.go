package analyzers

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"regexp"
	"strings"

	"insider/models"
	"insider/models/reports"
)

var librariesExtractor *regexp.Regexp

var pieFlagDetector *regexp.Regexp

func init() {
	librariesExtractor = regexp.MustCompile(`\s*(.*)*\s\(compatibility\sversion\s(.*),\scurrent\sversion\s(.*)\)`)
	pieFlagDetector = regexp.MustCompile(`Flags:\s*.*(PIE)`)
}

// GetPlistFromJSON takes care of the special structure for Plist files
// in decompiled apps, searching for a file called Info.plist inside
// the given directory in `dirname` param
func GetPlistFromJSON(dirname string) (models.Plist, error) {
	var plist models.Plist

	infoPlistFilename := filepath.Join(dirname, "Info.plist")

	infoPlistContent, err := ioutil.ReadFile(infoPlistFilename)
	if err != nil {
		return models.Plist{}, err
	}

	if err := json.Unmarshal(infoPlistContent, &plist); err != nil {
		return models.Plist{}, err
	}

	return plist, nil
}

// ParseLibsFile gets the `libs.e` file from the decompiler
// and parses it back to []models.Library
func ParseLibsFile(dirname, sastID string) (libraries []reports.Library, err error) {
	libsFilename := filepath.Join(dirname, "libs.e")

	libsFileContent, err := ioutil.ReadFile(libsFilename)

	if err != nil {
		return
	}

	rawLibraries := librariesExtractor.FindAllStringSubmatch(string(libsFileContent), -1)

	for _, rawLibrary := range rawLibraries {
		var name string
		var source string

		rawLibFullname := rawLibrary[1]

		rawNameWithExt := strings.Split(rawLibFullname, "/")
		rawName := fmt.Sprintf("%s/%s", rawNameWithExt[len(rawNameWithExt)-2], rawNameWithExt[len(rawNameWithExt)-1])

		if strings.Contains(rawName, "dylib") {
			name = strings.Split(rawName, filepath.Ext(rawName))[0]
			source = "Shared Library (dyld Cache)"
		} else if strings.Contains(rawLibFullname, "System/Library/Frameworks") {
			name = rawName
			source = "System Library"
		} else {
			name = rawName
			source = "External"
		}

		library := reports.Library{
			SastID:               sastID,
			Name:                 name,
			Source:               source,
			Version:              rawLibrary[3],
			CompatibilityVersion: rawLibrary[2],
		}

		libraries = append(libraries, library)
	}

	return
}

// ParseHeaderFile searches for a file called `header.e` left
// from Wall-E preprocessing and decompilation, parses it and
// add the findings to the vulnerabilities array inside the `report`
func ParseHeaderFile(dirname string, report *reports.IOSReport) error {
	headerFilename := filepath.Join(dirname, "header.e")

	headerContent, err := ioutil.ReadFile(headerFilename)

	if err != nil {
		return err
	}

	if !pieFlagDetector.Match(headerContent) {
		vulnerability := reports.Vulnerability{
			VulnerabilityID: "INS-1",
			CWE:             "CWE-119",
			CVSS:            2,
			Rank:            "baixa/média",
			ShortMessage:    "Não foi encontrado a flag do compilador PIE (Opção: -pie) no app",
			LongMessage:     "O app não está compilado com a flag PIE (Position Independent Executable). Isso permite que o iOS utilize da funcionalidade de ASLR (Address Space Layout Randomization), uma proteção nativa da memória do dispotivo para mitigação de exploits que exigem conhecimento de endereços de memória como Buffer overflows.",
		}

		report.Vulnerabilities = append(report.Vulnerabilities, vulnerability)
	}

	return nil
}
