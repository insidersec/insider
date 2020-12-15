package insider_test

import (
	"context"
	"testing"

	"github.com/insidersec/insider"
	"github.com/insidersec/insider/report"
	"github.com/insidersec/insider/testutil"
	"github.com/stretchr/testify/assert"
)

func TestAnalyzeAndroid(t *testing.T) {
	testcases := []struct {
		name          string
		folder        string
		err           bool
		permissions   int
		vulnerability int
		subPackages   int
		services      int
		receivers     int
		activities    int
	}{
		{
			name:        "Test Android analyzer with permissions",
			folder:      "testdata/android/camera",
			err:         false,
			permissions: 1,
			activities:  1,
		},
		{
			name:        "Test Android analyzer with multiples manifests",
			folder:      "testdata/android/multiples",
			err:         false,
			permissions: 34,
			subPackages: 2,
			services:    4,
			receivers:   2,
			activities:  3,
		},
		{
			name:        "Test Android analyzer without manifests",
			folder:      "testdata/android/empty",
			err:         false,
			permissions: 0,
			subPackages: 0,
			services:    0,
			receivers:   0,
			activities:  0,
		},
	}

	for _, tt := range testcases {
		t.Run(tt.name, func(t *testing.T) {

			a := insider.NewAndroidAnalyzer(testutil.NewTestLogger(t))

			rep, err := a.Analyze(context.Background(), tt.folder)

			if tt.err {
				assert.NotNil(t, err, "Expected not nil error to analyze android")
			} else {
				assert.Nil(t, err, "Expected nil error to analyze android: %v", err)
			}

			r, ok := rep.(report.AndroidReporter)
			assert.True(t, ok, "Expected AndroidReporter type on return")

			assert.Equal(t, tt.permissions, len(r.ManifestPermissions), "Expected equal permissions")
			assert.Equal(t, tt.vulnerability, len(r.Vulnerabilities), "Expected equal vulnerabilities")
			assert.Equal(t, tt.subPackages, len(r.AndroidInfo.SubPackageNames), "Expected equal sub packages")
			assert.Equal(t, tt.services, len(r.Services), "Expected equal services")
			assert.Equal(t, tt.receivers, len(r.BroadcastReceivers), "Expected equal receivers")
			assert.Equal(t, tt.activities, len(r.AvailableActivities), "Expected equal activities")

		})
	}

}
