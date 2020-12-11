package lib

import (
	"strings"
	"testing"

	"github.com/insidersec/insider/models/reports"

	"github.com/stretchr/testify/assert"
)

func TestAnalyzeAndroidInternalApp(t *testing.T) {
	dirname := "testdata/kotlin/"
	report := reports.AndroidReport{}

	err := AnalyzeAndroidSource(dirname, "1", &report, "kotlin")

	assert.Nil(t, err, "Unexpected error on AnalyzeAndroidSource: %v", err)

	assert.Falsef(t, len(report.Vulnerabilities) <= 0, "AnalyzeSource should have found something in the internal app")
}

func TestAnalyzeAndroidInternalAppWithProblemsInStringsXML(t *testing.T) {
	dirname := "testdata/kotlin/"
	report := reports.AndroidReport{}

	err := AnalyzeAndroidSource(dirname, "1", &report, "android")
	assert.Nil(t, err, "Unexpected error on AnalyzeAndroidSource: %v", err)

	found := false
	for _, vulnerability := range report.Vulnerabilities {
		if vulnerability.CWE == "CWE-312" {
			if strings.Contains(vulnerability.Class, "strings.xml") {
				t.Logf("Found %s at file %s, line %d as expected.", vulnerability.CWE, vulnerability.Class, vulnerability.Line)
				found = true
			}
		}
	}

	assert.True(t, found, "Should have found problem in strings.xml file")

}
