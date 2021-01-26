package engine_test

import (
	"context"
	"regexp"
	"testing"

	"github.com/insidersec/insider/engine"
	"github.com/insidersec/insider/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEngineScan(t *testing.T) {

	testcases := []struct {
		name            string
		engine          *engine.Engine
		lines           int
		vulnerabilities int
	}{
		{
			name:            "Test without ignore files",
			engine:          engine.New(testutil.NewTestRuleBuilder(t), []*regexp.Regexp{}, 4, testutil.NewTestLogger(t)),
			lines:           118,
			vulnerabilities: 3,
		},
		{
			name: "Test with ignore files",
			engine: engine.New(testutil.NewTestRuleBuilder(t), []*regexp.Regexp{
				regexp.MustCompile("ios/*"),
			}, 4, testutil.NewTestLogger(t)),
			lines:           70,
			vulnerabilities: 3,
		},
	}

	for _, tt := range testcases {
		t.Run(tt.name, func(t *testing.T) {
			r, err := tt.engine.Scan(context.Background(), "testdata/scan")
			require.Nil(t, err)

			result, ok := r.(engine.Result)
			require.True(t, ok)

			assert.Equal(t, tt.lines, result.Lines, "Expected equal total lines")
			assert.Equal(t, tt.vulnerabilities, len(result.Vulnerabilities), "Expected equal vulnerabilities")
		})
	}

}
