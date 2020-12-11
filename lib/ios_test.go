package lib

import (
	"testing"

	"github.com/insidersec/insider/models/reports"

	"github.com/stretchr/testify/assert"
)

func TestAnalyzeIOSInternalApp(t *testing.T) {
	dirname := "testdata/IOSApp/"
	report := reports.IOSReport{}

	err := AnalyzeIOSSource(dirname, "42", &report, "swift")
	assert.Nil(t, err, "Unexpected error on AnalyzeIOSSource: %v", err)

	assert.False(t, len(report.Vulnerabilities) <= 0, "AnalyzeSource should have found something in the internal app.")

	t.Logf("Found %d vulnerabilities.", len(report.Vulnerabilities))
}
