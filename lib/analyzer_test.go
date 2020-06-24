package lib

import (
	"testing"

	"inmetrics/eve/models/reports"
	"inmetrics/eve/visitor"
)

func TestExtractHardcodedInfo(t *testing.T) {
	dirname := visitor.SolvePathToTestFolder("exampleiOSApp")

	report := reports.Report{}

	err := ExtractHardcodedInfo(dirname, &report)

	if err != nil {
		t.Fatal(err)
	}

	if len(report.DRA.URLs) <= 0 {
		t.Fatal("Should have found a URL")
	}

	t.Log(report.DRA.URLs)
	t.Log(report.DRA.Emails)
}
