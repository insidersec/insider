package lib

import (
	"fmt"
	"log"
	"strconv"

	"github.com/insidersec/insider/lexer"
	"github.com/insidersec/insider/models"
	"github.com/insidersec/insider/visitor"
)

func formatClassInfo(filename string, line, column int) string {
	return fmt.Sprintf("%s (%s:%s)", filename, strconv.FormatInt(int64(line), 10), strconv.FormatInt(int64(column), 10))
}

// ConvertFindingToReport converts our internal data object for representing
// a weakness found in the source code being analyzed to the Vulnerability model
// to make a single reporting framework for all analysis
func ConvertFindingToReport(filename, displayName string, finding models.Finding) (vulnerability models.Vulnerability) {
	formattedClass := formatClassInfo(
		filename,
		finding.Line,
		finding.Column,
	)

	vulnerability = models.Vulnerability{
		Class:            displayName,
		Line:             finding.Line,
		Method:           finding.Sample,
		Column:           finding.Column,
		FileName:         formattedClass,
		CWE:              finding.Info.CWE,
		Severity:         finding.Info.Severity,
		LongMessage:      finding.Info.Description,
		Recomendation:    finding.Info.Recomendation,
		OWASPReferenceID: finding.Info.OWASPReferenceID,
	}

	return
}

// LoadsFilesAndRules loads up a given directory following the visitor rules for
// the language being analyzed, so we can speed up analysis time by removing useless files
// and also loads the rules for the given language.
// The returned errors should be handled by the caller.
func LoadsFilesAndRules(dirname, tech string) (files []string, loadedRules []lexer.Rule, err error) {
	files, err = visitor.LoadSourceDir(dirname, tech)

	if err != nil {
		return
	}

	log.Printf("Found %d files to analyze.", len(files))

	loadedRules, err = lexer.LoadRules(tech)

	if err == nil {
		log.Printf("Loading %s ruleset. (%s rules)", tech, strconv.FormatInt(int64(len(loadedRules)), 10))
	}

	// Since even if there is an error we have to return it,
	// and we are using named parameters, we can safely return now.
	return
}
