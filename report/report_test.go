package report_test

import (
	"bytes"
	"testing"

	"github.com/insidersec/insider/report"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReportResumeConsole(t *testing.T) {
	r := report.Report{
		Base: report.Base{
			DRA: []report.DRA{{
				Data:     "testing",
				Type:     "email",
				FilePath: "foo/bar",
			}},
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
	r := report.Report{
		Base: report.Base{
			DRA: []report.DRA{{
				Data:     "testing",
				Type:     "email",
				FilePath: "foo/bar",
			}},
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
	}

	out := bytes.NewBufferString("")

	err := r.Html(out)
	require.Nil(t, err)
	require.True(t, len(out.Bytes()) != 0)

}

func TestReportJson(t *testing.T) {
	r := report.Report{
		Base: report.Base{
			DRA: []report.DRA{{
				Data:     "testing",
				Type:     "email",
				FilePath: "foo/bar",
			}},
		},
	}

	out := bytes.NewBufferString("")

	err := r.Json(out)
	require.Nil(t, err)
	require.True(t, len(out.Bytes()) != 0)

}

func TestReportCleanDRA(t *testing.T) {
	r := report.Report{
		Base: report.Base{
			DRA: []report.DRA{
				{Data: "foobar@tmp.com.br", Type: "email", FilePath: "/tmp/foo/bar/bla.go"},
				{Data: "foobar@tmp.com.br", Type: "email", FilePath: "/tmp/foo/bar/baz.go"},
				{Data: "baz@tmp.com.br", Type: "email", FilePath: "/tmp/foo/bar/x.go"},
				{Data: "whatever@tmp.com.br", Type: "email", FilePath: "/tmp/foo/bar/y.go"},
			},
		},
	}

	err := r.CleanDRA("/tmp/foo")

	assert.Nil(t, err, "Expected nil error to clean duplicated DRAS: %v", err)
	assert.Equal(t, len(r.DRA), 3, "Expected report withou duplicated DRAs")
}
