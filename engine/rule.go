package engine

import "context"

type Rule interface {
	Match(InputFile) ([]Issue, error)
}

type RuleBuilder interface {
	Build(ctx context.Context, techs ...Language) ([]Rule, error)
}

type RuleSet map[Language][]Rule

func NewRuleSet() RuleSet {
	return make(RuleSet)
}

func (r RuleSet) Register(tech Language, rules []Rule) {
	r[tech] = rules
}

func (r RuleSet) RegisteredFor(tech Language) []Rule {
	if rules, found := r[tech]; found {
		return rules
	}
	return nil
}
