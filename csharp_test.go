package insider_test

import (
	"context"
	"testing"

	"github.com/insidersec/insider"
	"github.com/insidersec/insider/report"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAnalyzeCsharp(t *testing.T) {
	analyzer := insider.NewCsharpAnalyzer()

	r, err := analyzer.Analyze(context.Background(), "")

	require.Nil(t, err)
	assert.Equal(t, report.Report{}, r)
}
