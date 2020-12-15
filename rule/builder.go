package rule

import (
	"context"
	"fmt"

	"github.com/insidersec/insider/engine"
)

type RuleBuilder struct{}

func NewRuleBuilder() *RuleBuilder {
	return &RuleBuilder{}
}

func (r RuleBuilder) Build(ctx context.Context, techs ...engine.Language) ([]engine.Rule, error) {
	rules := make([]engine.Rule, 0)

	for _, tech := range techs {
		switch tech {
		case engine.Core:
			rules = append(rules, CoreRules...)
		case engine.Csharp:
			rules = append(rules, CsharpRules...)
		case engine.Javascript:
			rules = append(rules, JavascriptRules...)
		case engine.Android, engine.Java:
			rules = append(rules, AndroidRules...)
		case engine.Ios:
			rules = append(rules, IosRules...)
		default:
			return nil, fmt.Errorf("invalid tech %s", string(tech))
		}

	}

	return rules, nil
}
