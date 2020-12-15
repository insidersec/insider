package engine_test

import (
	"testing"

	"github.com/insidersec/insider/engine"
	"github.com/insidersec/insider/report"
	"github.com/stretchr/testify/assert"
)

func TestAnalyzeDRA(t *testing.T) {

	testcases := []struct {
		name    string
		path    string
		content string
		dras    []report.DRA
	}{
		{
			name: "Test DRA email with less than two characters",
			path: "/tmp/foo/bar",
			content: `
let email = "%@seven.com"
let other_email = "fo@bar.com"
let invalid_email = "@seven.com"
			`,
			dras: []report.DRA{},
		},
		{
			name: "Test DRA url auth",
			path: "/tmp/foo/bar",
			content: `
let url = "https://username:password@example.com"
			`,
			dras: []report.DRA{
				{
					Data:     "password@example.com",
					Type:     "email",
					FilePath: "/tmp/foo/bar",
				},
				{
					Data:     "https://username:password@example.com",
					Type:     "url auth",
					FilePath: "/tmp/foo/bar",
				},
			},
		},
		{
			name: "Test DRA email",
			path: "/tmp/foo/bar",
			content: `
let email = "tmp@gmail.com"
			`,
			dras: []report.DRA{
				{
					Data:     "tmp@gmail.com",
					Type:     "email",
					FilePath: "/tmp/foo/bar",
				},
			},
		},
		{
			name: "Test DRA email with uppercase",
			path: "/tmp/foo/bar",
			content: `
let email = "Tmp@gmail.com"
let email = "TMP@gmail.com"
let email = "TMP@GMAIL.COM"
			`,
			dras: []report.DRA{
				{
					Data:     "Tmp@gmail.com",
					Type:     "email",
					FilePath: "/tmp/foo/bar",
				},
				{
					Data:     "TMP@gmail.com",
					Type:     "email",
					FilePath: "/tmp/foo/bar",
				},
				{
					Data:     "TMP@GMAIL.COM",
					Type:     "email",
					FilePath: "/tmp/foo/bar",
				},
			},
		},
		{
			name: "Test DRA url",
			path: "/tmp/foo/bar",
			content: `
let url = "http://foobar.com.br"
			`,
			dras: []report.DRA{
				{
					Data:     "http://foobar.com.br",
					Type:     "url",
					FilePath: "/tmp/foo/bar",
				},
			},
		},
		{
			name: "Test DRA url with invalid urls",
			path: "/tmp/foo/bar",
			content: `
let url = "http://foobar.com.br"
let bla = "https://baz.com.br"
"url": git@gitlab.com/repo
"foo": "https://registry.yarnpkg.org/"
"foo": "https://registry.npmjs.org/"
			`,
			dras: []report.DRA{
				{
					Data:     "http://foobar.com.br",
					Type:     "url",
					FilePath: "/tmp/foo/bar",
				},
				{
					Data:     "https://baz.com.br",
					Type:     "url",
					FilePath: "/tmp/foo/bar",
				},
			},
		},
	}

	for _, tt := range testcases {
		t.Run(tt.name, func(t *testing.T) {
			dra := engine.AnalyzeDRA(tt.path, tt.content)

			assert.Equal(t, tt.dras, dra, "Expected equal dras: %v", dra)

		})
	}
}
