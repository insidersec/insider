package lib

import (
	"testing"

	"inmetrics/eve/models/reports"
	"inmetrics/eve/visitor"
)

func TestAnalyzeProjectObjectModel(t *testing.T) {
	report := reports.Report{}

	dirname := visitor.SolvePathToTestFolder("")

	err := AnalyzeProjectObjectModel(dirname, "42", &report)

	if err != nil {
		t.Fatal(err)
	}

	if report.Info.Name == "" {
		t.Fatal("Should have found project name")
	}

	if report.Info.Version == "" {
		t.Fatal("Should have found project version")
	}

	if report.Info.Name != "com.fasterxml.jackson.dataformat:jackson-dataformat-csv" {
		t.Fatal("Found wrong name")
	}

	if len(report.Libraries) <= 0 {
		t.Fatal("Should have found libraries")
	}
}
