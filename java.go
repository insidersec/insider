package insider

import (
	"context"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"

	"github.com/insidersec/insider/report"
)

// POM or the Project Object Model is the fundamental unit
// on a Maven based project.
type POM struct {
	Name          string            `xml:"name"`
	Version       string            `xml:"version"`
	GroupID       string            `xml:"groupId"`
	PackagingMode string            `xml:"packaging"`
	ArtifactID    string            `xml:"artifactId"`
	Description   string            `xml:"description"`
	Dependencies  []POMDependencies `xml:"dependencies>dependency"`
}

// POMDependencies holds data about external objects of
// a POM project
type POMDependencies struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
}

type JavaAnalyzer struct {
	logger *log.Logger
}

func NewJavaAnalyzer(logger *log.Logger) JavaAnalyzer {
	return JavaAnalyzer{
		logger: logger,
	}
}

func (a JavaAnalyzer) Analyze(ctx context.Context, dir string) (report.Reporter, error) {
	var r report.Report
	a.logger.Println("Analysing Java dependencies")
	if err := a.analyzeProjectObjectModel(ctx, &r, dir); err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}
	}
	return r, nil
}

func (a JavaAnalyzer) analyzeProjectObjectModel(ctx context.Context, rep *report.Report, dir string) error {

	file := filepath.Join(dir, "pom.xml")
	b, err := ioutil.ReadFile(file)
	if err != nil {
		return err
	}

	var pom POM
	if err := xml.Unmarshal(b, &pom); err != nil {
		return err
	}

	rep.Info.Name = convertGroupIDToName(pom.GroupID, pom.ArtifactID)
	rep.Info.Version = pom.Version

	for _, projectDependency := range pom.Dependencies {
		reportLibrary := report.Library{
			Name: convertGroupIDToName(
				projectDependency.GroupID,
				projectDependency.ArtifactID,
			),
			Version: projectDependency.Version,
		}

		rep.Libraries = append(rep.Libraries, reportLibrary)
	}

	return nil
}

func convertGroupIDToName(groupID, artifactID string) string {
	return fmt.Sprintf("%s:%s", groupID, artifactID)
}
