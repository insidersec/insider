package report_test

import (
	"bytes"
	"testing"

	"github.com/insidersec/insider/report"
	"github.com/stretchr/testify/require"
)

func TestReportResumeConsole(t *testing.T) {
	r := report.Report{
		Base: report.Base{
			Vulnerabilities: []report.Vulnerability{
				{
					CWE:  "CWE-123",
					CVSS: 5,
				},
				{
					CWE:  "CWE-456",
					CVSS: 7,
				},
			},
		},
		Info: report.SASTInfo{
			SecurityScore: 5,
			AverageCVSS:   7,
		},
	}

	outResume := bytes.NewBufferString("")
	r.Resume(outResume)
	require.True(t, len(outResume.Bytes()) != 0)

	outConsole := bytes.NewBufferString("")
	r.Console(outConsole)
	require.True(t, len(outConsole.Bytes()) != 0)
}

func TestReportHtml(t *testing.T) {
	testcases := []struct {
		name   string
		report report.Reporter
	}{
		{
			name: "Test default report",
			report: report.Report{
				Base: report.Base{
					Vulnerabilities: []report.Vulnerability{
						{
							CWE:  "CWE-123",
							CVSS: 5,
						},
					},

					Total:  5,
					High:   5,
					Medium: 0,
					Low:    0,
				},
				Info: report.SASTInfo{
					SecurityScore: 5,
				},
			},
		},
		{
			name: "Test Android report",
			report: report.AndroidReporter{
				Base: report.Base{
					Vulnerabilities: []report.Vulnerability{
						{
							CWE:  "CWE-123",
							CVSS: 5,
						},
					},

					Total:  5,
					High:   5,
					Medium: 0,
					Low:    0,
				},
				AndroidInfo: report.AndroidInfo{
					SecurityScore: 5,
				},
			},
		},
		{
			name: "Test Ios report",
			report: report.IOSReporter{
				Base: report.Base{
					Vulnerabilities: []report.Vulnerability{
						{
							CWE:  "CWE-123",
							CVSS: 5,
						},
					},

					Total:  5,
					High:   5,
					Medium: 0,
					Low:    0,
				},
				IOSInfo: report.IOSInfo{
					SecurityScore: 5,
				},
			},
		},
	}

	for _, tt := range testcases {
		t.Run(tt.name, func(t *testing.T) {

			out := bytes.NewBufferString("")

			err := tt.report.Html(out)
			require.Nil(t, err, "Expected nil error, got %v", err)
			require.True(t, len(out.Bytes()) != 0)

		})
	}

}

func TestReportJson(t *testing.T) {
	r := report.Report{
		Base: report.Base{
			None:   10,
			Medium: 4,
			Low:    2,
			High:   7,
		},
	}

	out := bytes.NewBufferString("")

	err := r.Json(out)
	require.Nil(t, err)
	require.True(t, len(out.Bytes()) != 0)

}
