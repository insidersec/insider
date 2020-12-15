package insider

import (
	"context"
	"log"

	"github.com/insidersec/insider/report"
)

type TechAnalyzer interface {
	Analyze(ctx context.Context, dir string) (report.Reporter, error)
}

type Engine interface {
	Scan(ctx context.Context, dir string) (report.Result, error)
}

type Analyzer struct {
	logger *log.Logger
	tech   TechAnalyzer
	engine Engine
}

func NewAnalyzer(engine Engine, tech TechAnalyzer, logger *log.Logger) *Analyzer {
	return &Analyzer{
		logger: logger,
		engine: engine,
		tech:   tech,
	}
}

func (a *Analyzer) Analyze(ctx context.Context, dir string) (report.Reporter, error) {
	a.logger.Printf("Starting analysis")
	base, err := a.tech.Analyze(ctx, dir)
	if err != nil {
		return nil, err
	}

	a.logger.Printf("Starting source code analysis")
	result, err := a.engine.Scan(ctx, dir)
	if err != nil {
		return nil, err
	}

	return result.ToReporter(dir, base)
}
