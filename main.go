package main

import (
	"flag"
	"fmt"
	"github.com/insidersec/insider/supervisors"
	"log"
	"os"
	"path/filepath"
	"strings"
)

var tech string
var noHTML bool
var noJSON bool
var noBanner bool
var ignoreWarnings bool

var targetFolder string

// formatWarningMessage will display every message in red
// IF and ONLY IF the output stream handler deals with it.
func formatWarningMessage(message string) string {
	return fmt.Sprintf("\033[0;31m%s\033[0;0m", message)
}

func init() {
	// Required flags
	flag.StringVar(&tech, "tech", "", "Specify which technology ruleset to load. (Valid values are: android, ios, csharp, javascript)\n-tech javascript\n-tech csharp")
	flag.StringVar(&targetFolder, "target", "", "Specify where to look for files to run the specific ruleset.\n-target <folder>\n-target <myprojectfolder>")

	// Optional flags
	flag.BoolVar(&ignoreWarnings, "force", false, "Overwrite the results directory. Insider does not overwrite the results directory by default - Optional")
	flag.BoolVar(&noHTML, "no-html", false, "Skips the report generation in the HTML format - Optional")
	flag.BoolVar(&noJSON, "no-json", false, "Skips the report generation in the JSON format - Optional")
	flag.BoolVar(&noBanner, "no-banner", false, "Skips the banner printing (Useful for CI/Docker environments) - Optional")
}

func main() {
	log.SetPrefix("[INSIDER]: ")

	flag.Parse()

	if !noBanner {
		printBanner()
	}

	if tech == "" {
		log.Fatal("Should specify a technology (Valid values are: android, ios, csharp, javascript)\n-tech javascript\n-tech csharp")
	}

	if targetFolder == "" {
		log.Fatal("Should specify a target folder\n-target <folder>\n-target <myprojectfolder>")
	}

	resultsFolderStat, err := os.Stat(supervisors.ResultFolderName)

	if err != nil {
		if os.IsNotExist(err) {
			// If the error is not the NotExistError, we have to create
			// the folderisResultDirCreated
			log.Println("Creating results folder...")
			err = os.Mkdir(supervisors.ResultFolderName, 0700)

			if err != nil {
				log.Fatal(err)
				return
			}
		} else {
			log.Fatal(err)
			return
		}
	}

	// If the Stat function report us that it is a directory
	// it means that the CLI is running in a folder that already
	// have the supervisors.ResultFolderName folder in it.

	//We should only overwrite it if the flag -force is passed
	if resultsFolderStat != nil && resultsFolderStat.IsDir() {
		log.Println(formatWarningMessage("WARNING: The results folder already exists."))
		if !ignoreWarnings {
			log.Println(formatWarningMessage("Cancelling run to prevent report overwrite"))
			return
		}

		log.Println(formatWarningMessage("But you gave the permission to continue >:D"))
	}

	physicalPath, err := filepath.Abs(targetFolder)

	if err != nil {
		log.Fatal(err)
		return
	}

	codeInfo := supervisors.SourceCodeInfo{
		Tech:             tech,
		PhysicalPath:     physicalPath,
		ForceOverwriting: ignoreWarnings,
	}

	switch tech {
	case "android":
		log.Println("Starting analysis for Android app")

		err = supervisors.RunAndroidSourceCodeAnalysis(codeInfo)

		log.Println("Finished analysis for Android app")

	case "ios":
		log.Println("Starting analysis for iOS app")

		err = supervisors.RunIOSCodeAnalysis(codeInfo)

		log.Println("Finished analysis for iOS app")

	case "csharp":
		log.Println("Starting analysis for C# app")

		err = supervisors.RunCSharpSourceCodeAnalysis(codeInfo)

		log.Println("Finished analysis for C# application")

	case "javascript":
		log.Println("Starting analysis for JavaScript app")

		err = supervisors.RunJSSourceCodeAnalysis(codeInfo)

		log.Println("Finished JavaScript analysis")
	default:
		helpText := ", please choose android, ios, csharp or javascript"

		if strings.Contains(tech, "c") || strings.Contains(tech, "C") {
			helpText = ", did you mean csharp ?"
		}

		if strings.Contains(tech, "js") || strings.Contains(tech, "j") {
			helpText = ", did you mean javascript ?"
		}

		if strings.Contains(tech, "swift") {
			helpText = ", did you mean ios ?"
		}

		if strings.Contains(tech, "kotlin") {
			helpText = ", did you mean android ?"
		}

		log.Fatalf("Invalid technology%s", helpText)
	}

	if err != nil {
		log.Fatal(err)
		return
	}

	os.Exit(0)
}
