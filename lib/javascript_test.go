package lib

import (
	"testing"

	"github.com/insidersec/insider/models/reports"

	"github.com/stretchr/testify/assert"
)

func TestAnalyzeJSDependencies(t *testing.T) {
	report := reports.Report{}
	sastID := "1"

	dirname := "testdata/javascript/"

	err := AnalyzeJSDependencies(dirname, sastID, &report)

	assert.Nil(t, err, "Unexpected error from AnalyzeJSDependencies: %v", err)
	assert.False(t, len(report.Libraries) <= 0, "Should have found any library")

}
