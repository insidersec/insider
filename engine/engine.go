package engine

import (
	"context"
	"log"
	"sync"

	"github.com/insidersec/insider/report"
)

type Engine struct {
	logger      *log.Logger
	ruleBuilder RuleBuilder
	jobs        int
}

func New(ruleBuilder RuleBuilder, jobs int, logger *log.Logger) *Engine {
	return &Engine{
		logger:      logger,
		ruleBuilder: ruleBuilder,
		jobs:        jobs,
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
	}
	return scanner.Process()
}
