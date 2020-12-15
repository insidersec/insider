package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"
	"time"

	"github.com/insidersec/insider"
	"github.com/insidersec/insider/engine"
	"github.com/insidersec/insider/rule"
)

const (
	npmAdvisoryURL string = "https://registry.npmjs.org/-/npm/v1/security/audits"
	npmUserAgent   string = "npm-registry-fetch@5.0.1/node@v12.5.0+x64 (linux)"
)

var (
	flagTech   = flag.String("tech", "", "Specify which technology ruleset to load. (Valid values are: android, ios, csharp, javascript)\n-tech javascript\n-tech csharp")
	flagTarget = flag.String("target", "", "Specify where to look for files to run the specific ruleset.\n-target <folder>\n-target <myprojectfolder>")

	flagJobs     = flag.Int("jobs", 4, "Number of analysis to execute in parallel")
	flagForce    = flag.Bool("force", false, "Overwrite the report file name. Insider does not overwrite the results directory by default - Optional")
	flagNoHTML   = flag.Bool("no-html", false, "Skips the report generation in the HTML format - Optional")
	flagNoJSON   = flag.Bool("no-json", false, "Skips the report generation in the JSON format - Optional")
	flagSecurity = flag.Float64("security", 0, "Set the Security level, values between 0 and 100")
	flagVerbose  = flag.Bool("v", false, "Set true for verbose output")
	flagVersion  = flag.Bool("version", false, "Show version and quit with exit code 0")
)

func usage() {
	fmt.Fprintf(os.Stderr, "Insider is the CLI project from the Insider Application Security Team for the community\n")
	fmt.Fprintf(os.Stderr, "Usage:\n")
	flag.PrintDefaults()
	fmt.Fprintf(os.Stderr, `
Example of use:
	insider -tech javascript -target myprojectfolder
	insider -tech=android -target=myandroidfolder
	insider -tech android -target <myfolder> -no-html
`)
}

func main() {
	prepareVersionInfo()

	flag.Usage = usage
	flag.Parse()

	if *flagVersion {
		fmt.Printf("Version: %s\nGit commit: %s\nBuild date: %s\nOS/Arch: %s/%s\n", Version, GitCommit, BuildDate, runtime.GOOS, runtime.GOARCH)
		os.Exit(0)
	}

	if *flagTech == "" {
		fmt.Fprintf(os.Stderr, "Should specify a tech to execute analysis\n")
		os.Exit(1)
	}

	if *flagTarget == "" {
		fmt.Fprintf(os.Stderr, "Should specify a target folder\n-target <folder>\n-target <myprojectfolder>\n")
		os.Exit(1)
	}
	logger := log.New(os.Stderr, "[insider] ", log.LstdFlags)

	techAnalyzer, err := techAnalyzer(*flagTech, logger)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	engine := engine.New(rule.NewRuleBuilder(), *flagJobs, logger)
	analyzer := insider.NewAnalyzer(engine, techAnalyzer, logger)

	report, err := analyzer.Analyze(context.Background(), *flagTarget)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if !*flagNoJSON {
		name := "report.json"
		if !*flagForce {
			currentTime := time.Now()
			name = fmt.Sprintf("report-%v.json", currentTime.Format("20060102150405"))
		}
		out, err := os.Create(name)
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
		name := "report.html"
		if !*flagForce {
			currentTime := time.Now()
			name = fmt.Sprintf("report-%v.html", currentTime.Format("20060102150405"))
		}
		out, err := os.Create(name)
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
