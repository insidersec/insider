package testutil

import (
	"context"
	"regexp"
	"testing"

	"github.com/insidersec/insider/engine"
	"github.com/insidersec/insider/rule"
)

type fakeRuleBuilder struct {
	t testing.TB
}

func (b fakeRuleBuilder) Build(ctx context.Context, techs ...engine.Language) ([]engine.Rule, error) {
	return NewTestRules(b.t), nil
}

func NewTestRuleBuilder(t testing.TB) engine.RuleBuilder {
	return fakeRuleBuilder{
		t: t,
	}
}

func NewTestRules(t testing.TB) []engine.Rule {
	return []engine.Rule{
		rule.Rule{
			ExactMatch:  regexp.MustCompile(`(password\s*=\s*['|"][\w\!\@\#\$\%\&\*\(\)\s]+['|"])`),
			Description: "foo bar baz",
			AverageCVSS: 7,
			CWE:         "CWE-312",
		},
		rule.Rule{
			Or:          []*regexp.Regexp{regexp.MustCompile("_srand"), regexp.MustCompile("_random")},
			Description: "foo bar baz",
			AverageCVSS: 4.5,
			CWE:         "CWE-338",
		},
	}
}
