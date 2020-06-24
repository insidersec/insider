package lib

import (
	"testing"

	"inmetrics/eve/models/reports"
	"inmetrics/eve/visitor"
)

func TestAnalyzeJSDependencies(t *testing.T) {
	report := reports.Report{}
	sastID := "1"

	dirname := visitor.SolvePathToTestFolder("")

	err := AnalyzeJSDependencies(dirname, sastID, &report)

	if err != nil {
		t.Fatal(err.Error())
	}

	if len(report.Libraries) <= 0 {
		t.Fatal("Should have found any library")
	}
}
