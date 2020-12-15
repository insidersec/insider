package report_test

import (
	"testing"

	"github.com/insidersec/insider/report"
	"github.com/stretchr/testify/assert"
)

func TestReportCleanDRA(t *testing.T) {
	r := report.Report{
		DRA: []report.DRA{
			{Data: "foobar@tmp.com.br", Type: "email", FilePath: "/tmp/foo/bar/bla.go"},
			{Data: "foobar@tmp.com.br", Type: "email", FilePath: "/tmp/foo/bar/baz.go"},
			{Data: "baz@tmp.com.br", Type: "email", FilePath: "/tmp/foo/bar/x.go"},
			{Data: "whatever@tmp.com.br", Type: "email", FilePath: "/tmp/foo/bar/y.go"},
		},
	}

	err := r.CleanDRA("/tmp/foo")

	assert.Nil(t, err, "Expected nil error to clean duplicated DRAS: %v", err)
	assert.Equal(t, len(r.DRA), 3, "Expected report withou duplicated DRAs")
}
