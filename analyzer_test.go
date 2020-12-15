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
					Dra:             []report.DRA{{}},
					Vulnerabilities: []report.Vulnerability{{}, {}},
					Size:            10,
				},
			},
			expectedReport: report.Report{
				Info: report.SASTInfo{
					Size: "10 Bytes",
				},
				DRA: []report.DRA{{
					FilePath: ".",
				}},
				Vulnerabilities: []report.Vulnerability{{}, {}},
				LibraryIssues:   []report.LibraryVulnerability{{}, {}},
				High:            0,
				Medium:          2,
				Low:             0,
				Total:           2,
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
					Dra:             []report.DRA{{}},
					Vulnerabilities: []report.Vulnerability{{}, {}},
					Size:            57,
				},
			},
			expectedReport: report.AndroidReporter{
				AndroidInfo: report.AndroidInfo{
					Title: "testing",
					Size:  "57 Bytes",
				},
				DRA: []report.DRA{{
					FilePath: ".",
				}},
				Vulnerabilities: []report.Vulnerability{{}, {}},
				High:            0,
				Medium:          2,
				Low:             0,
				Total:           2,
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
					Dra:             []report.DRA{{}},
					Vulnerabilities: []report.Vulnerability{{}, {}},
					Size:            57,
				},
			},
			expectedReport: report.IOSReporter{
				IOSInfo: report.IOSInfo{
					AppName: "testing",
					Size:    "57 Bytes",
				},
				DRA: []report.DRA{{
					FilePath: ".",
				}},
				Vulnerabilities: []report.Vulnerability{{}, {}},
				High:            0,
				Medium:          2,
				Low:             0,
				Total:           2,
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
