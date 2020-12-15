package insider_test

import (
	"context"
	"testing"

	"github.com/insidersec/insider"
	"github.com/insidersec/insider/report"
	"github.com/insidersec/insider/testutil"
	"github.com/stretchr/testify/assert"
)

func TestAnalyzeJava(t *testing.T) {
	testcases := []struct {
		name      string
		dir       string
		err       bool
		libraries int
	}{
		{
			name:      "Test Java maven source analyzer",
			dir:       "testdata/java/maven",
			err:       false,
			libraries: 1,
		},
		{
			name:      "Test Java withou pom.xml",
			dir:       "testdata/java/without_pom",
			err:       false,
			libraries: 0,
		},
	}

	a := insider.NewJavaAnalyzer(testutil.NewTestLogger(t))

	for _, tt := range testcases {
		t.Run(tt.name, func(t *testing.T) {
			rep, err := a.Analyze(context.Background(), tt.dir)

			if tt.err {
				assert.NotNil(t, err, "Expected not nil error to analyze android")
			} else {
				assert.Nil(t, err, "Expected nil error to analyze ios: %v", err)
			}

			r, ok := rep.(report.Report)
			assert.True(t, ok, "Expected Report type on return")

			assert.Equal(t, tt.libraries, len(r.Libraries), "Expected equal libraries")
		})
	}

}
