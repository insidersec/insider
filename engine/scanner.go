package engine

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"sync"

	"github.com/insidersec/insider/report"
)

type spawnFn func(file InputFile, rules []Rule) error

type Language string

func (l Language) rules() []Language {
	rules := []Language{Core}
	switch l {
	case Javascript:
		rules = append(rules, Javascript)
	case Java, Android:
		rules = append(rules, Java, Android)
	case Csharp:
		rules = append(rules, Csharp)
	case Ios:
		rules = append(rules, Ios)
	}
	return rules
}

const (
	Javascript Language = "Javascript"
	Java       Language = "Java"
	Android    Language = "Android"
	Csharp     Language = "C#"
	Ios        Language = "Ios"
	Core       Language = "Core"
)

var languages = map[string]Language{
	".js": Javascript,
	".ts": Javascript,

	".java": Java,

	".kt": Android,

	".cs":     Csharp,
	".cshtml": Csharp,
	".aspx":   Csharp,

	".swift": Ios,
	".obj":   Ios,
	".h":     Ios,
	".m":     Ios,
}

type scanner struct {
	logger      *log.Logger
	mutext      *sync.Mutex
	wg          *sync.WaitGroup
	result      *Result
	exclude     []*regexp.Regexp
	ruleBuilder RuleBuilder
	ruleSet     RuleSet
	errors      []error
	ch          chan bool
	ctx         context.Context
	dir         string
}

func (s *scanner) Process() (Result, error) {
	if err := filepath.Walk(s.dir, s.Walk); err != nil {
		return Result{}, err
	}
	s.wg.Wait()
	if len(s.errors) > 0 {
		return Result{}, fmt.Errorf("%v", s.errors) // TODO format errors
	}
	close(s.ch)
	s.result.SecurityScore = CalculateSecurityScore(s.result.AverageCVSS)
	return *s.result, nil
}

func (s *scanner) Walk(path string, info os.FileInfo, err error) error {
	if err != nil {
		return err
	}
	if info.IsDir() || info.Mode()&os.ModeSymlink != 0 || s.ignore(path) {
		return nil
	}

	// Check if the context timeout has been exceeded or cancelled.
	if err := s.ctx.Err(); err != nil {
		return err
	}

	rules, err := s.loadRules(path)
	if err != nil {
		return err
	}

	if len(rules) == 0 {
		s.logger.Printf("Ignoring file %s\n", path)
		return nil
	}
	s.result.Size += info.Size()

	inputFile, err := NewInputFile(s.dir, path)
	if err != nil {
		return err
	}
	s.logger.Printf("Load %d rules to file %s\n", len(rules), inputFile.DisplayName)

	s.spawn(s.analyseFile, inputFile, rules)
	return nil
}

func (s *scanner) spawn(fn spawnFn, file InputFile, rules []Rule) {
	s.wg.Add(1)
	s.ch <- true

	go func() {
		defer func() {
			s.wg.Done()
			<-s.ch
		}()

		if err := fn(file, rules); err != nil {
			s.mutext.Lock()
			s.errors = append(s.errors, err)
			s.mutext.Unlock()
		}
	}()
}

func (s *scanner) analyseFile(file InputFile, rules []Rule) error {
	issues, err := AnalyzeFile(file, rules)
	if err != nil {
		return err
	}

	s.mutext.Lock()
	s.result.Lines += len(file.NewlineIndexes)
	for _, issue := range issues {
		vulnerability := issueToVulnerability(file.Name, file.DisplayName, issue)
		if vulnerability.CVSS > s.result.AverageCVSS {
			s.result.AverageCVSS = vulnerability.CVSS
		}
		s.result.Vulnerabilities = append(s.result.Vulnerabilities, vulnerability)
	}
	s.mutext.Unlock()

	return nil
}

func (s *scanner) loadRules(file string) ([]Rule, error) {
	s.mutext.Lock()
	defer s.mutext.Unlock()

	language, err := s.language(file)
	if err != nil {
		return nil, err
	}

	// Cached rules
	if rules := s.ruleSet.RegisteredFor(language); rules != nil {
		return rules, nil
	}

	// Build new rules
	rules, err := s.ruleBuilder.Build(s.ctx, language.rules()...)
	if err != nil {
		return nil, err
	}

	// Cache new rules
	s.ruleSet.Register(language, rules)

	return rules, nil
}

func (s *scanner) language(file string) (Language, error) {
	ext := filepath.Ext(file)

	if lang, found := languages[ext]; found {
		return lang, nil
	}

	return Core, nil
}

func (s *scanner) ignore(path string) bool {
	for _, re := range s.exclude {
		if re.MatchString(path) {
			return true
		}
	}
	return false
}

func issueToVulnerability(filename, displayName string, issue Issue) report.Vulnerability {
	classDisplay := formatClassInfo(displayName, issue.Line, issue.Column)
	class := formatClassInfo(filename, issue.Line, issue.Column)

	return report.Vulnerability{
		VulnerabilityID: issue.VulnerabilityID,
		Line:            issue.Line,
		Class:           class,
		Method:          issue.Sample,
		Column:          issue.Column,
		CWE:             issue.Info.CWE,
		CVSS:            issue.Info.CVSS,
		ClassMessage:    classDisplay,
		Severity:        issue.Info.Severity,
		Description:     issue.Info.Description,
		Recomendation:   issue.Info.Recomendation,
	}
}

func formatClassInfo(filename string, line, column int) string {
	return fmt.Sprintf("%s (%s:%s)", filename, strconv.FormatInt(int64(line), 10), strconv.FormatInt(int64(column), 10))
}
