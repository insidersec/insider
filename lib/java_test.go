package lib

import (
	"testing"

	"github.com/insidersec/insider/models/reports"

	"github.com/stretchr/testify/assert"
)

func TestAnalyzeProjectObjectModel(t *testing.T) {
	report := reports.Report{}

	dirname := "testdata/java/"

	err := AnalyzeProjectObjectModel(dirname, "42", &report)

	assert.Nil(t, err, "Unexpected error on AnalyzeProjectObjectModel: %v", err)
	assert.NotEqual(t, report.Info.Name, "", "Should have found project name")
	assert.NotEqual(t, report.Info.Version, "", "Should have found project version")
	assert.NotEqual(t, len(report.Libraries), 0, "Should have found libraries")
}
