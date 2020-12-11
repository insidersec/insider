package lib

import (
	"github.com/insidersec/insider/models/reports"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractHardcodedInfo(t *testing.T) {
	dirname := "testdata/IOSApp/"
	sasID := "42"

	report := reports.Report{}

	err := ExtractHardcodedInfo(dirname, sasID, &report)
	assert.Nil(t, err, "Unexpected error on ExtractHardcodedInfo: %v")

	assert.Equal(t, report.Info.SastID, sasID, "Different sasIDs")

	assert.NotEqual(t, len(report.DRA), 0, "Should have found a DRA", dirname)

}
