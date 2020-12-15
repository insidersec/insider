package engine_test

import (
	"context"
	"testing"

	"github.com/insidersec/insider/engine"
	"github.com/insidersec/insider/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEngineScan(t *testing.T) {
	e := engine.New(testutil.NewTestRuleBuilder(t), 4, testutil.NewTestLogger(t))

	r, err := e.Scan(context.Background(), "testdata/scan")
	require.Nil(t, err)

	result, ok := r.(engine.Result)
	require.True(t, ok)

	assert.Equal(t, 4, len(result.Dra), "Expected equal dras")
	assert.Equal(t, 121, result.Lines, "Expected equal total lines")
	assert.Equal(t, 3, len(result.Vulnerabilities), "Expected equal vulnerabilities")
}
