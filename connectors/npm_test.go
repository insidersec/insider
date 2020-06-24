package connectors

import (
	"testing"

	"encoding/json"
	"io/ioutil"
	"os"
	"path/filepath"

	"inmetrics/eve/models"
)

func solveToTestFolder(path string) string {
	pathPrefix := os.Getenv("GOPATH")

	fullPath := []string{pathPrefix}
	fullPath = append(fullPath, "src/inmetrics/eve/test")
	fullPath = append(fullPath, path)

	return filepath.Join(fullPath...)
}

func TestAuditLibraries(t *testing.T) {
	var packageJSON models.PackageJSON
	filename := solveToTestFolder("package.json")

	t.Logf("Reading %s", filename)

	packageJSONData, err := ioutil.ReadFile(filename)

	if err != nil {
		t.Fatal(err.Error())
	}

	err = json.Unmarshal(packageJSONData, &packageJSON)

	if err != nil {
		t.Fatal(err.Error())
	}

	result, err := AuditLibraries(packageJSON)

	if err != nil {
		t.Fatal(err.Error())
	}

	for _, advisory := range result.Advisories {
		t.Logf("Found %s in %s", advisory.Title, advisory.ModuleName)
		t.Logf("Overview: %s", advisory.Overview)
		t.Logf("Recomendation: %s", advisory.Recomendation)
	}
}
