package engine

import (
	"context"
	"log"
	"regexp"
	"sync"

	"github.com/insidersec/insider/report"
)

type Engine struct {
	logger      *log.Logger
	exclude     []*regexp.Regexp
	ruleBuilder RuleBuilder
	jobs        int
	dra         bool
}

func New(ruleBuilder RuleBuilder, exclude []*regexp.Regexp, jobs int, logger *log.Logger) *Engine {
	return newEngine(ruleBuilder, exclude, jobs, false, logger)
}

func NewWithDRA(ruleBuilder RuleBuilder, exclude []*regexp.Regexp, jobs int, logger *log.Logger) *Engine {
	return newEngine(ruleBuilder, exclude, jobs, true, logger)
}

func newEngine(ruleBuilder RuleBuilder, exclude []*regexp.Regexp, jobs int, dra bool, logger *log.Logger) *Engine {
	return &Engine{
		logger:      logger,
		exclude:     exclude,
		ruleBuilder: ruleBuilder,
		jobs:        jobs,
		dra:         dra,
	}
}

func (e *Engine) Scan(ctx context.Context, dir string) (report.Result, error) {
	e.logger.Printf("Analysing files on directory %s\n", dir)
	scanner := &scanner{
		logger:      e.logger,
		mutext:      new(sync.Mutex),
		wg:          new(sync.WaitGroup),
		ch:          make(chan bool, e.jobs),
		errors:      make([]error, 0),
		ctx:         ctx,
		result:      new(Result),
		ruleBuilder: e.ruleBuilder,
		ruleSet:     NewRuleSet(),
		dir:         dir,
		exclude:     e.exclude,
		dra:         e.dra,
	}
	return scanner.Process()
}
