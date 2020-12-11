package main

import (
	"flag"
	"fmt"
	"github.com/insidersec/insider/supervisors"
	"github.com/insidersec/insider/util"
	"log"
	"os"
)

func main() {

	var tech, lang, targetFolder string
	var noHTML, noJSON, noBanner, ignoreWarnings, verbose bool
	var security int
	var flaglabel = map[string]string{
		"tech":   "Specify which technology ruleset to load. (Valid values are: android, ios, csharp, javascript)\n-tech javascript\n-tech csharp",
		"target": "Specify where to look for files to run the specific ruleset.\n-target <folder>\n-target <myprojectfolder>",
	}

	flag.StringVar(&tech, "tech", "", flaglabel["tech"])
	flag.StringVar(&targetFolder, "target", "", flaglabel["target"])

	// Optional flags
	flag.BoolVar(&ignoreWarnings, "force", false, "Overwrite the report file name. Insider does not overwrite the results directory by default - Optional")
	flag.BoolVar(&noHTML, "no-html", false, "Skips the report generation in the HTML format - Optional")
	flag.BoolVar(&noJSON, "no-json", false, "Skips the report generation in the JSON format - Optional")
	flag.BoolVar(&noBanner, "no-banner", false, "Skips the banner printing (Useful for CI/Docker environments) - Optional")
	flag.IntVar(&security, "security", 0, "Set the Security level, values ​​between 0 and 100")
	flag.BoolVar(&verbose, "v", false, "Set true for verbose output")

	flag.Usage = func() {
		fmt.Println("Insider is the CLI project from the Insider Application Security Team for the community")
		fmt.Println("Usage :")
		flag.PrintDefaults()
		fmt.Println("Example of use :\n\tinsider -tech javascript -target myprojectfolder \n" +
			"\tinsider -tech=android -target=myandroidfolder \n" +
			"\tinsider -tech android -target <myfolder> -no-html")
	}

	log.SetPrefix("[INSIDER]: ")
	flag.Parse()

	if !noBanner {
		util.PrintLogo()
	}
	var flagerr []string
	switch tech {
	case "android", "ios", "csharp", "javascript":
	case "":
		fallthrough
	default:
		flagerr = append(flagerr, flaglabel["tech"])
	}

	lang = "en"

	if targetFolder == "" {
		flagerr = append(flagerr, "Should specify a target folder\n-target <folder>\n-target <myprojectfolder>")
	}

	getpath, _ := os.Getwd()

	if targetFolder == "." || targetFolder == getpath {
		flagerr = append(flagerr, "Please put the insider out of the folder to be analyzed!")
	}

	if len(flagerr) >= 1 {
		for _, err := range flagerr {
			log.Printf("Error: %v\n", err)
		}
		os.Exit(1)
	}

	componentID := ""
	sastID := ""
	version := ""
	path := "all"

	var err error

	destinationFileName := "" // where zip file is

	codeInfo := supervisors.SourceCodeInfo{
		Path:         path,
		Tech:         tech,
		SastID:       sastID,
		Version:      version,
		ComponentID:  componentID,
		PhysicalPath: destinationFileName,
	}

	switch tech {
	case "android":
		log.Printf("Starting analysis for Android target %s", targetFolder)
		err = supervisors.RunAndroidSourceCodeAnalysis(codeInfo, lang, targetFolder, noJSON, noHTML, security, verbose, ignoreWarnings)
		log.Printf("Finished analysis for Android app #%s", targetFolder)
	case "csharp":
		log.Printf("Starting analysis for C# app #%s", sastID)
		err = supervisors.RunCSharpSourceCodeAnalysis(codeInfo, lang, targetFolder, noJSON, noHTML, security, verbose, ignoreWarnings)
		log.Printf("Finished analysis for C# application #%s", sastID)
	case "javascript":
		log.Printf("Starting analysis for JavaScript/TypeScript app #%s", sastID)
		err = supervisors.RunJSSourceCodeAnalysis(codeInfo, lang, targetFolder, noJSON, noHTML, security, verbose, ignoreWarnings)
		log.Println("Finished JavaScript/TypeScript analysis")
	case "ios":
		log.Printf("Starting analysis for iOS app #%s", sastID)
		err = supervisors.RunIOSCodeAnalysis(codeInfo, lang, targetFolder, noJSON, noHTML, security, verbose, ignoreWarnings)
		log.Printf("Finished analysis for iOS app #%s", sastID)
	default:
		log.Println("Could not analyze package...")
	}

	if err != nil {
		log.Printf("Error: %v\n", err)
		os.Exit(1)
	}

}
