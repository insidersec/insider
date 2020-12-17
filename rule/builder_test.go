package rule_test

import (
	"context"
	"testing"

	"github.com/insidersec/insider/engine"
	"github.com/insidersec/insider/rule"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRuleBuilder(t *testing.T) {
	testcases := []struct {
		name      string
		languages []engine.Language
		err       bool
		rules     int
	}{
		{
			name:      "Test load multiple rules",
			languages: []engine.Language{engine.Javascript, engine.Csharp, engine.Core, engine.Android, engine.Ios},
			rules:     155,
		},
		{
			name:      "Test load single rule",
			languages: []engine.Language{engine.Core},
			rules:     37,
		},
		{
			name:      "Test load invalid rule",
			languages: []engine.Language{engine.Language("Invalid-tech")},
			err:       true,
		},
	}

	builder := rule.NewRuleBuilder()

	for _, tt := range testcases {
		t.Run(tt.name, func(t *testing.T) {
			rules, err := builder.Build(context.Background(), tt.languages...)

			if tt.err {
				require.NotNil(t, err)
			} else {
				require.Nil(t, err)
			}

			assert.Equal(t, tt.rules, len(rules))
		})
	}

}
