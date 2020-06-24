package lib

import (
	"encoding/json"
	"testing"

	"inmetrics/eve/models/reports"
	"inmetrics/eve/visitor"
)

func TestAnalyzeIOSInternalApp(t *testing.T) {
	sourceCodeFolder := visitor.SolvePathToTmpFolder("ios")

	report := reports.IOSReport{}

	err := AnalyzeIOSSource(sourceCodeFolder, "42", &report)

	if err != nil {
		t.Fatal(err.Error())
	}

	if len(report.Vulnerabilities) <= 0 {
		t.Fatal("AnalyzeSource should have found something in the internal app.")
	}

	data, err := json.Marshal(report)

	if err != nil {
		t.Fatal(err)
	}

	t.Logf("Found %d vulnerabilities.", len(report.Vulnerabilities))
	t.Log(string(data))
}
