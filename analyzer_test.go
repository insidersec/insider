package insider_test

import (
	"context"
	"testing"

	"github.com/insidersec/insider"
	"github.com/insidersec/insider/engine"
	"github.com/insidersec/insider/report"
	"github.com/insidersec/insider/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeEngine struct {
	result report.Result
	err    error
}

func (e fakeEngine) Scan(ctx context.Context, dir string) (report.Result, error) {
	return e.result, e.err
}

type fakeTechAnalyzer struct {
	report report.Reporter
	err    error
}

func (a fakeTechAnalyzer) Analyze(ctx context.Context, dir string) (report.Reporter, error) {
	return a.report, a.err
}

func TestAnalyzer(t *testing.T) {

	testcases := []struct {
		name           string
		tech           insider.TechAnalyzer
		engine         insider.Engine
		err            bool
		expectedReport report.Reporter
	}{
		{
			name: "Test Analyze with default report generated",
			tech: fakeTechAnalyzer{
				report: report.Report{
					LibraryIssues: []report.LibraryVulnerability{{}, {}},
				},
			},
			engine: fakeEngine{
				result: &engine.Result{
					Vulnerabilities: []report.Vulnerability{
						{CVSS: 0}, {CVSS: 2.3}, {CVSS: 6.7},
					},
					Size: 10,
				},
			},
			expectedReport: report.Report{
				Info: report.SASTInfo{
					Size: "10 Bytes",
				},
				Base: report.Base{
					Vulnerabilities: []report.Vulnerability{{CVSS: 0}, {CVSS: 2.3}, {CVSS: 6.7}},
					None:            1,
					High:            0,
					Medium:          1,
					Low:             1,
					Total:           3,
				},
				LibraryIssues: []report.LibraryVulnerability{{}, {}},
			},
		},
		{
			name: "Test Analyze with Android report generated",
			tech: fakeTechAnalyzer{
				report: report.AndroidReporter{
					AndroidInfo: report.AndroidInfo{
						Title: "testing",
					},
				},
			},
			engine: fakeEngine{
				result: &engine.Result{
					Vulnerabilities: []report.Vulnerability{{CVSS: 6.7}, {CVSS: 8.1}, {CVSS: 7.2}, {CVSS: 9.2}},
					Size:            57,
				},
			},
			expectedReport: report.AndroidReporter{
				AndroidInfo: report.AndroidInfo{
					Title: "testing",
					Size:  "57 Bytes",
				},
				Base: report.Base{
					Vulnerabilities: []report.Vulnerability{{CVSS: 6.7}, {CVSS: 8.1}, {CVSS: 7.2}, {CVSS: 9.2}},
					None:            0,
					Low:             0,
					Medium:          1,
					High:            2,
					Critical:        1,
					Total:           4,
				},
			},
		},
		{
			name: "Test Analyze with Ios report generated",
			tech: fakeTechAnalyzer{
				report: report.IOSReporter{
					IOSInfo: report.IOSInfo{
						AppName: "testing",
					},
				},
			},
			engine: fakeEngine{
				result: &engine.Result{
					Vulnerabilities: []report.Vulnerability{
						{CVSS: 3.9}, {CVSS: 4.0}, {CVSS: 6.9}, {CVSS: 7.0}, {CVSS: 8.9}, {CVSS: 9.8},
					},
					Size: 57,
				},
			},
			expectedReport: report.IOSReporter{
				IOSInfo: report.IOSInfo{
					AppName: "testing",
					Size:    "57 Bytes",
				},
				Base: report.Base{
					Vulnerabilities: []report.Vulnerability{
						{CVSS: 3.9}, {CVSS: 4.0}, {CVSS: 6.9}, {CVSS: 7.0}, {CVSS: 8.9}, {CVSS: 9.8},
					},
					None:     0,
					Low:      0,
					Medium:   1,
					High:     2,
					Critical: 1,
					Total:    4,
				},
			},
		},
	}

	for _, tt := range testcases {
		t.Run(tt.name, func(t *testing.T) {
			analyzer := insider.NewAnalyzer(tt.engine, tt.tech, testutil.NewTestLogger(t))

			r, err := analyzer.Analyze(context.Background(), "")

			if tt.err {
				require.NotNil(t, err)
			} else {
				require.Nil(t, err)
			}

			assert.Equal(t, tt.expectedReport, r)
		})
	}

}
