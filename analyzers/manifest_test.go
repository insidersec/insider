package analyzers

import (
	"testing"

	"inmetrics/eve/models/reports"
	"inmetrics/eve/visitor"
)

func TestManifestAnalysis(t *testing.T) {
	dirname := visitor.SolvePathToTestFolder("AndroidManifest.xml")
	report := reports.AndroidReport{}

	err := AnalyzeAndroidManifest(dirname, "23", &report)

	if err != nil {
		t.Fatal(err.Error())
	}

	if len(report.ManifestPermissions) <= 0 {
		t.Fatal("Should have found permissions.")
	}

	permissionIsMissing := true
	for _, permission := range report.ManifestPermissions {
		if permission.Title == "android.permission.INTERNET" {
			t.Logf("Package name: %s", report.AndroidInfo.PackageName)
			t.Logf("Target SDK: %s", report.AndroidInfo.TargetSDK)
			t.Logf("Minimum SDK: %s", report.AndroidInfo.MinimumSDK)
			t.Logf("Maximum SDK: %s", report.AndroidInfo.MaximumSDK)
			t.Logf("Version info: %s", report.AndroidInfo.AndroidVersionName)
			t.Logf("Version info: %s", report.AndroidInfo.AndroidVersionCode)

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
