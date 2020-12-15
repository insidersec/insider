package insider_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/insidersec/insider"
	"github.com/insidersec/insider/report"
	"github.com/insidersec/insider/testutil"
	"github.com/stretchr/testify/assert"
)

type fakeNpm struct {
	result insider.AuditResult
}

func (npm fakeNpm) AuditLibraries(insider.PackageJSON) (insider.AuditResult, error) {
	return npm.result, nil

}

func TestJavaScriptAnalyze(t *testing.T) {
	// Expected base package.json based on testdata/javascript/package.json
	expectedPkgJSON := insider.PackageJSON{
		Name:    "teste",
		Version: "0.1.0",
		Dependencies: map[string]string{
			"express": "^4.17.1",
		},
	}

	mockAuditResult := insider.AuditResult{
		Advisories: map[string]insider.Advisory{
			"express": {},
		},
	}

	npm := fakeNpm{
		result: mockAuditResult,
	}

	testcases := []struct {
		name        string
		dir         string
		err         bool
		pkgJSON     insider.PackageJSON
		auditResult insider.AuditResult
		libraries   int
	}{
		{
			name:        "Test with package.json",
			dir:         "testdata/javascript",
			err:         false,
			pkgJSON:     expectedPkgJSON,
			auditResult: mockAuditResult,
			libraries:   1,
		},
		{
			name:        "Test without package.json",
			dir:         "testdata/javascript/foo",
			err:         false,
			pkgJSON:     insider.PackageJSON{},
			auditResult: insider.AuditResult{},
			libraries:   0,
		},
	}

	for _, tt := range testcases {
		t.Run(tt.name, func(t *testing.T) {
			analyzer := insider.NewJavaScriptAnalyzer(npm, testutil.NewTestLogger(t))

			rep, err := analyzer.Analyze(context.Background(), tt.dir)

			if tt.err {
				assert.NotNil(t, err, "Expected not nil error to analyze javascript")
			} else {
				assert.Nil(t, err, "Expected nil error to analyze javascript: %v", err)
			}

			r, ok := rep.(report.Report)
			assert.True(t, ok, "Expected type report.Report on return of javascript.Analyze")

			assert.Equal(t, tt.libraries, len(r.Libraries), "Expected %d library on report", tt.libraries)
		})
	}

}

func TestNPMAuditLibraries(t *testing.T) {
	fakeResponse := `{"actions":[],"advisories":{"express": {}},"muted":[],"metadata":{"vulnerabilities":{"info":0,"low":0,"moderate":0,"high":0,"critical":0},"dependencies":21,"devDependencies":0,"optionalDependencies":0,"totalDependencies":21}}`

	testServer := testutil.NewHttpTestServer([]byte(fakeResponse), http.StatusOK)
	defer func() { testServer.Close() }()

	npm := insider.NewNPMAdvisory(testServer.URL, "agent", 20*time.Second)

	fakePKGJson := insider.PackageJSON{
		Name:    "teste",
		Version: "0.1.0",
		Dependencies: map[string]string{
			"express": "^4.17.1",
		},
	}

	expectedAdvisories := map[string]insider.Advisory{
		"express": {},
	}

	r, err := npm.AuditLibraries(fakePKGJson)

	assert.Nil(t, err, "Expected nil error to audit libraries %v", err)
	assert.Equal(t, r.Advisories, expectedAdvisories)
}
