package analyzers

import (
	"path/filepath"
	"testing"

	"github.com/insidersec/insider/models"
)

func TestManifestAnalysis(t *testing.T) {
	dirname := filepath.FromSlash("testdata/AndroidManifest.xml")
	report := models.AndroidReport{}

	err := AnalyzeAndroidManifest(dirname, &report)

	if err != nil {
		t.Fatal(err.Error())
	}

	if len(report.ManifestPermissions) <= 0 {
		t.Fatal("Should have found permissions.")
	}

	permissionIsMissing := true
	for _, permission := range report.ManifestPermissions {
		if permission.Title == "android.permission.INTERNET" {
			permissionIsMissing = false
			break
		}

		if permission.Description == "" {
			t.Fatal("Error while loading manifest permission data.")
		}
	}

	if permissionIsMissing {
		t.Fatal("Should have found the INTERNET permission.")
	}
}
