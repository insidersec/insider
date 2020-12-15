package engine_test

import (
	"errors"
	"testing"

	"github.com/insidersec/insider/engine"
	"github.com/stretchr/testify/assert"
)

type fakeRule struct {
	issues []engine.Issue
	err    error
}

func (r fakeRule) Match(i engine.InputFile) ([]engine.Issue, error) {
	return r.issues, r.err
}

func TestAnalyseFile(t *testing.T) {
	testcases := []struct {
		name           string
		inputFile      engine.InputFile
		rules          []engine.Rule
		expectedIssues []engine.Issue
		err            error
	}{
		{
			name:      "Test match issues",
			inputFile: engine.InputFile{},
			rules: []engine.Rule{
				fakeRule{
					issues: []engine.Issue{{}, {}},
				},
			},
			expectedIssues: []engine.Issue{{}, {}},
		},
		{
			name:      "Test not match issues",
			inputFile: engine.InputFile{},
			rules: []engine.Rule{
				fakeRule{},
			},
			expectedIssues: []engine.Issue{},
		},
		{
			name:      "Test not match issues",
			inputFile: engine.InputFile{},
			rules: []engine.Rule{
				fakeRule{err: errors.New("testing")},
			},
			err: errors.New("testing"),
		},
	}

	for _, tt := range testcases {
		t.Run(tt.name, func(t *testing.T) {
			issues, err := engine.AnalyzeFile(tt.inputFile, tt.rules)

			assert.Equal(t, tt.err, err)
			assert.Equal(t, tt.expectedIssues, issues)
		})
	}

}
