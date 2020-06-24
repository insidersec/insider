package lib

import (
	"encoding/json"
	"strings"
	"testing"

	"inmetrics/eve/models/reports"
	"inmetrics/eve/visitor"
)

func TestAnalyzeAndroidInternalApp(t *testing.T) {
	sourceCodeFolder := visitor.SolvePathToTmpFolder("987123")
	report := reports.AndroidReport{}

	err := AnalyzeAndroidSource(sourceCodeFolder, "1", &report)

	if err != nil {
		t.Fatal(err.Error())
	}

	if len(report.Vulnerabilities) <= 0 {
		t.Fatal("AnalyzeSource should have found something in the internal app.")
	}

	_, err = json.Marshal(report)

	if err != nil {
		t.Fatal(err)
	}
}

func TestAnalyzeAndroidInternalAppWithProblemsInStringsXML(t *testing.T) {
	sourceCodeFolder := visitor.SolvePathToTmpFolder("teste")
	report := reports.AndroidReport{}

	err := AnalyzeAndroidSource(sourceCodeFolder, "1", &report)

	if err != nil {
		t.Fatal(err.Error())
	}

	if len(report.Vulnerabilities) <= 0 {
		t.Fatal("AnalyzeSource should have found something in the internal app.")
	}

	found := false
	for _, vulnerability := range report.Vulnerabilities {
		if vulnerability.CWE == "CWE-312" {
			if strings.Contains(vulnerability.Class, "strings.xml") {
				t.Logf("Found %s at file %s, line %d as expected.", vulnerability.CWE, vulnerability.Class, vulnerability.Line)
				found = true
			}
		}
	}

	if !found {
		t.Fatal("Should have found problem in strings.xml file")
	}

	_, err = json.Marshal(report)

	if err != nil {
		t.Fatal(err)
	}
}
