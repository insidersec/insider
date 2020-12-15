package insider_test

import (
	"context"
	"testing"

	"github.com/insidersec/insider"
	"github.com/insidersec/insider/report"
	"github.com/insidersec/insider/testutil"
	"github.com/stretchr/testify/assert"
)

func TestAnalyzeIOS(t *testing.T) {
	testcases := []struct {
		name          string
		folder        string
		err           bool
		vulnerability int
		libraries     int
	}{
		{
			name:      "Test IOS source analyzer",
			folder:    "testdata/ios/source",
			err:       false,
			libraries: 3,
		},
		{
			name:      "Test IOS source analyzer without plist file",
			folder:    "testdata/ios/source/DVIA-v2/DVIA-v2",
			err:       false,
			libraries: 0,
		},
	}

	analyzer := insider.NewIosAnalyzer(testutil.NewTestLogger(t))

	for _, tt := range testcases {
		t.Run(tt.name, func(t *testing.T) {
			rep, err := analyzer.Analyze(context.Background(), tt.folder)

			if tt.err {
				assert.NotNil(t, err, "Expected not nil error to analyze android")
			} else {
				assert.Nil(t, err, "Expected nil error to analyze ios: %v", err)
			}

			r, ok := rep.(report.IOSReporter)
			assert.True(t, ok, "Expected Report type on return")

			assert.Equal(t, tt.vulnerability, len(r.Vulnerabilities), "Expected equal vulnerabilities")
			assert.Equal(t, tt.libraries, len(r.Libraries), "Expected equal libraries")
		})
	}

}
