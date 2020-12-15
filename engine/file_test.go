package engine_test

import (
	"testing"

	"github.com/insidersec/insider/engine"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFindInputFiles(t *testing.T) {
	testcases := []struct {
		name       string
		dir        string
		includeDir bool
		fn         engine.FinderFunc
		expected   int
	}{
		{
			name:       "Find input files without dir",
			dir:        "testdata/inputfile",
			includeDir: false,
			fn:         func(path string) bool { return true },
			expected:   2,
		},
		{
			name:       "Find input files with dir",
			dir:        "testdata/inputfile",
			includeDir: true,
			fn:         func(path string) bool { return true },
			expected:   4,
		},
	}

	for _, tt := range testcases {
		t.Run(tt.name, func(t *testing.T) {
			res, err := engine.FindInputFiles(tt.dir, tt.includeDir, tt.fn)

			require.Nil(t, err)
			assert.Equal(t, tt.expected, len(res))
		})
	}
}
