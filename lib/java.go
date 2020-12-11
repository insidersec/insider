package lib

import (
	"encoding/xml"
	"fmt"
	"log"
	"regexp"

	"github.com/insidersec/insider/models"
	"github.com/insidersec/insider/models/reports"
	"github.com/insidersec/insider/visitor"
)

var pomFinder *regexp.Regexp

func init() {
	pomFinder = regexp.MustCompile(`pom\.xml`)
}

func convertGroupIDToName(groupID, artifactID string) string {
	return fmt.Sprintf("%s:%s", groupID, artifactID)
}

func findPOM(filename string) bool {
	return pomFinder.MatchString(filename)
}

// AnalyzeProjectObjectModel parses and analyzes the pom.xml file for Java projects
func AnalyzeProjectObjectModel(dirname, sastID string, report *reports.Report) error {
	log.Println("Starting pom.xml analysis")
	pomFiles, err := visitor.FindFiles(dirname, false, findPOM)

	if err != nil {
		return err
	}

	var pom models.POM
	for _, pomFile := range pomFiles {
		err := xml.Unmarshal([]byte(pomFile.Content), &pom)

		if err != nil {
			continue
		}
	}

	report.Info.Name = convertGroupIDToName(pom.GroupID, pom.ArtifactID)
	report.Info.Version = pom.Version

	for _, projectDependency := range pom.Dependencies {
		reportLibrary := reports.Library{
			SastID: sastID,
			Name: convertGroupIDToName(
				projectDependency.GroupID,
				projectDependency.ArtifactID,
			),
			Version: projectDependency.Version,
		}

		report.Libraries = append(report.Libraries, reportLibrary)
	}

	log.Println("Finished pom.xml analysis")

	return nil
}
