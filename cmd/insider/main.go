package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/insidersec/insider"
	"github.com/insidersec/insider/engine"
	"github.com/insidersec/insider/rule"
)

const (
	npmAdvisoryURL string = "https://registry.npmjs.org/-/npm/v1/security/audits"
	npmUserAgent   string = "npm-registry-fetch@5.0.1/node@v12.5.0+x64 (linux)"
)

type arrayFlag []string

func (a arrayFlag) String() string {
	return strings.Join(a, " ")
}

func (a *arrayFlag) Set(s string) error {
	*a = append(*a, s)
	return nil
}

var (
	flagTech   = flag.String("tech", "", "Specify which technology ruleset to load")
	flagTarget = flag.String("target", "", "Specify where to look for files to run the specific ruleset")

	flagJobs = flag.Int("jobs", 4, "Number of analysis to execute in parallel")

	flagNoHTML = flag.Bool("no-html", false, "Skips the report generation in the HTML format")
	flagNoJSON = flag.Bool("no-json", false, "Skips the report generation in the JSON format")
	flagQuiet  = flag.Bool("quiet", false, "No output logs of execution")

	flagSecurity = flag.Float64("security", 0, "Set the Security level, values between 0 and 100 (default 0)")

	flagVerbose = flag.Bool("v", false, "Enable verbose output")
	flagVersion = flag.Bool("version", false, "Show version and quit with exit code 0")

	flagExclude arrayFlag
)

func usage() {
	fmt.Fprintln(os.Stderr, "insider is the CLI project from the Insider Application Security Team for the community")
	fmt.Fprintf(os.Stderr, "\nUsage:\n")
	flag.PrintDefaults()
	fmt.Fprintf(os.Stderr, `
Supported technologies:
	android
	java
	ios
	javascript
	csharp
	`)
	fmt.Fprintf(os.Stderr, `
Example of use:
	# Run JavaScript analysis on specific directoty
	insider -tech javascript -target <directory>

	# Run Android analysis on specific directoty and ignore html and json report
	insider -tech android -target <directory> -no-html -no-json

	# Run Java analysis on specific directoty with a base security value to fail
	insider -tech java -target <directory> -security 20

	# Run JavaScript analysis on specific directoty and exclude node_modules and test files
	insider -tech javascript -target <directory> -exclude tests/* -exclude node_modules/*

`)
}

func main() {
	prepareVersionInfo()

	flag.Var(&flagExclude, "exclude", "Patterns to exclude directory or files to analyze. Can be used multiple times")
	if err := flag.Set("exclude", ".git"); err != nil {
		fmt.Fprintf(os.Stderr, "Error exclude .git from analysis: %v\n", err)
		os.Exit(1)
	}

	flag.Usage = usage
	flag.Parse()

	if *flagVersion {
		fmt.Printf("Version: %s\nGit commit: %s\nBuild date: %s\nOS/Arch: %s/%s\n", Version, GitCommit, BuildDate, runtime.GOOS, runtime.GOARCH)
		os.Exit(0)
	}

	if *flagTech == "" {
		fmt.Fprintf(os.Stderr, "Error: Expected a technology type to analyze\n\n")
		flag.Usage()
		os.Exit(1)
	}

	if *flagTarget == "" {
		fmt.Fprintf(os.Stderr, "Error: Expected a target directory to analyze\n\n")
		flag.Usage()
		os.Exit(1)
	}
	var out io.Writer
	if *flagQuiet {
		out = ioutil.Discard
	} else {
		out = os.Stderr
	}

	logger := log.New(out, "[insider] ", log.LstdFlags)

	techAnalyzer, err := techAnalyzer(*flagTech, logger)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	exclude, err := buildExpressions(flagExclude)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	engine := engine.New(rule.NewRuleBuilder(), exclude, *flagJobs, logger)
	analyzer := insider.NewAnalyzer(engine, techAnalyzer, logger)

	report, err := analyzer.Analyze(context.Background(), *flagTarget)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if !*flagNoJSON {
		out, err := os.Create("report.json")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error to create json report: %v\n", err)
			os.Exit(1)
		}
		defer out.Close()
		if err := report.Json(out); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	}

	if !*flagNoHTML {
		out, err := os.Create("report.html")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error to create html report: %v\n", err)
			os.Exit(1)
		}
		defer out.Close()
		if err := report.Html(out); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	}

	report.Resume(os.Stdout)

	if *flagVerbose {
		report.Console(os.Stdout)
	}

	if securityScore := report.SecurityScore(); securityScore < *flagSecurity {
		log.Fatalf("Score Security %v lower then %v", securityScore, *flagSecurity)
	}

}

func buildExpressions(expressions []string) ([]*regexp.Regexp, error) {
	regexps := make([]*regexp.Regexp, 0, len(expressions))

	for _, expr := range expressions {
		re, err := regexp.Compile(expr)
		if err != nil {
			return nil, fmt.Errorf("compile %s: %w", expr, err)
		}
		regexps = append(regexps, re)
	}

	return regexps, nil
}

func techAnalyzer(tech string, logger *log.Logger) (insider.TechAnalyzer, error) {
	switch tech {
	case "android":
		return insider.NewAndroidAnalyzer(logger), nil
	case "csharp":
		return insider.NewCsharpAnalyzer(), nil
	case "java":
		return insider.NewJavaAnalyzer(logger), nil
	case "javascript":
		npm := insider.NewNPMAdvisory(npmAdvisoryURL, npmUserAgent, 20*time.Second)
		return insider.NewJavaScriptAnalyzer(npm, logger), nil
	case "ios":
		return insider.NewIosAnalyzer(logger), nil
	}
	return nil, fmt.Errorf("invalid tech %s", tech)
}
