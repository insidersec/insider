package analyzers

import (
	"testing"

	"inmetrics/eve/models/reports"
	"inmetrics/eve/visitor"
)

func TestAnalyzePList(t *testing.T) {
	testFolderLocation := visitor.SolvePathToTestFolder("exampleiOSApp")

	report := reports.IOSReport{}

	err := AnalyzePList(testFolderLocation, &report)

	if err != nil {
		t.Fatal(err.Error())
	}

	if report.IOSInfo.AppName == "" {
		t.Fatal("Should have found AppName")
	}

	if report.IOSInfo.AppName != "Podcasts" {
		t.Fatal("Found wrong appName")
	}
}
