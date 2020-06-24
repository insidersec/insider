package visitor

import (
	"crypto/md5"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

var sampleTemplate string
var scopeFinder *regexp.Regexp
var newlineFinder *regexp.Regexp
var scopeExtractor *regexp.Regexp

var languageExtensionDict map[string][]string
var languageImportExtractor map[string][]*regexp.Regexp

// InputFile represents a file to be analyzed
type InputFile struct {
	Name         string
	Content      string
	IsDir        bool
	DisplayName  string
	PhysicalPath string

	// Utilitaries for the engine
	FileImports     []string
	ImportReference string

	// Indexes for file reference

	// ScopeIndexes holds information about where is a scope declaration within the file
	ScopeIndexes [][]int
	// NewlineIndexes holds information about where is the line inside the string
	NewlineIndexes [][]int
	// NewlineLastIndexes represents the string start index of a '\n'
	NewlineLastIndexes []int
	// ScopeLastIndexes holds data about the current scope
	ScopeLastIndexes []int
}

// EvidenceSample holds data about where E.V.E found something
type EvidenceSample struct {
	// Unique identifier
	UniqueHash string

	Line          int
	Column        int
	Method        string
	Sample        string
	AfterContext  string
	BeforeContext string

	HazardousScope string
}

func init() {
	newlineFinder = regexp.MustCompile("\x0a")
	scopeFinder = regexp.MustCompile(`(.*private.*\s*|.*public.*\s*|.*fun.*\s*)(?:{|=)`)

	scopeExtractor = regexp.MustCompile(`([[:graph:]]*)(?:\(|\s*=)`)

	languageExtensionDict = map[string][]string{
		"swift": {
			".swift",
		},
		"js": {
			".js",
			".jsx",
			".ejs",
		},
		"csharp": {
			".cs",
		},
		"java": {
			".java",
		},
		"kotlin": {
			".kt",
		},
	}

	languageImportExtractor = map[string][]*regexp.Regexp{
		"swift":  {regexp.MustCompile(`import\s+(?:(?:typealias|struct|class|enum|protocol|let|var|func)\s+)*((?:.*(?:\.|))+)`)},
		"js":     {regexp.MustCompile(`(?:import\s+(?:.*|(?:\{.*\})*)\s+from\s+(?:'|")(?:(?:\.)+\/)*([a-zA-Z]+.*)(?:'|")|.*=\s*require\((?:'|")(?:(?:\.)+\/)*([a-zA-Z]+.*)(?:'|"))`)},
		"java":   {regexp.MustCompile(`import\s+(.*);`)},
		"kotlin": {regexp.MustCompile(`import\s+((?:[a-zA-Z]*(?:\.|))*)`), regexp.MustCompile(`package\s+((?:[a-zA-Z]*(?:\.|))*)`)},
		"csharp": {regexp.MustCompile(`using\s+((?:[a-zA-Z]*(?:\.|))*);`), regexp.MustCompile(`namespace\s+((?:[a-zA-Z]*(?:\.|))*)`)},
	}
}

func checkFileExtensionAndExtractImportsAndImportRef(dirname, filename, content string) (importReference string, importsOnFile []string) {
	fileExtension := filepath.Ext(filename)
	fileLanguage := ""

	if fileExtension != "" {
		for language, possibleExtensions := range languageExtensionDict {
			for _, extension := range possibleExtensions {
				if (fileExtension == extension) || (strings.Contains(fileExtension, extension)) {
					fileLanguage = language
					break
				}
			}

			if fileLanguage != "" {
				importsExtractor := languageImportExtractor[fileLanguage][0]

				if len(languageImportExtractor[fileLanguage]) > 1 {
					importRefExtractor := languageImportExtractor[fileLanguage][1]

					rawImportRef := importRefExtractor.FindStringSubmatch(content)

					if len(rawImportRef) > 0 {
						importReference = rawImportRef[len(rawImportRef)-1]
					}
				} else if fileLanguage == "js" {
					// As JS uses the filename itself as a way to import code
					// we need to handle special cases
					rawFilenameWithoutRootFolder := strings.Split(filename, dirname+"/")

					filenameWithoutRootFolder := strings.Join(rawFilenameWithoutRootFolder, "")

					filenameWithoutExt := filenameWithoutRootFolder[0 : len(filenameWithoutRootFolder)-len(filepath.Ext(filenameWithoutRootFolder))]

					importReference = filenameWithoutExt
				} else if fileLanguage == "java" {
					packageNameExtractor := regexp.MustCompile(`package\s+((?:[a-zA-Z]*(?:\.|))*)`)
					classNameExtractor := regexp.MustCompile(`public\s+.+class\s+([a-zA-Z]+)(?:\s+(?:extends|implements)|\{)`)

					rawPackageName := packageNameExtractor.FindStringSubmatch(content)
					rawClassName := classNameExtractor.FindStringSubmatch(content)

					if len(rawPackageName) > 0 && len(rawClassName) > 0 {
						packageName := rawPackageName[len(rawPackageName)-1]
						className := rawClassName[len(rawClassName)-1]

						importReference = fmt.Sprintf("%s.%s", packageName, className)
					}
				}

				rawImportsOnFile := importsExtractor.FindAllStringSubmatch(content, -1)

				for _, rawImport := range rawImportsOnFile {
					if len(rawImport) >= 1 {
						importsOnFile = append(importsOnFile, rawImport[len(rawImport)-1])
					}
				}

				return
			}
		}
	}

	return
}

func binarySearch(searchIndex int, collection []int) (foundIndex int) {
	foundIndex = sort.Search(
		len(collection),
		func(index int) bool { return collection[index] >= searchIndex },
	)
	return
}

func binarySearchAndFixIndexes(indexes []int, findingIndex int) (lineIndex, findingColumn int) {
	findingLineIndex := binarySearch(findingIndex, indexes)
	// Note about the crazy calculations about the column:

	// Since the given `findingIndex` is relative to the
	// beginning of the file, we need to subtract the finding index
	// from the closest `\n` mark in the file -1 (The newline symbol for the previous line.)
	if findingLineIndex < len(indexes) {
		lastNewlineSliceIndex := findingLineIndex - 1

		// Check to see if the finding wasn't in the first line.
		if lastNewlineSliceIndex <= 0 {
			lastNewlineSliceIndex = 0
		}

		lastNewlineIndexInTheFile := indexes[lastNewlineSliceIndex]
		findingColumn = findingIndex - lastNewlineIndexInTheFile

		// Since this is the slice index, + 1 should point to the real file position.
		lineIndex = findingLineIndex + 1
	} else {
		lineIndex = 0
		findingColumn = 0
	}

	return
}

/*
 ****************************************************************
 *                       Public Functions                       *
 ****************************************************************
 */

// NewInputFile creates a new InputFile,
// indexing all the '\n' to search, and also fills up some metadata
func NewInputFile(dirname, filename string, content []byte) InputFile {
	allNewlineIndexes := newlineFinder.FindAllIndex(content, -1)
	allScopesIndexes := scopeFinder.FindAllIndex(content, -1)

	newlineLastIndexes := make([]int, 0)

	for _, newLineLastIndex := range allNewlineIndexes {
		newlineLastIndexes = append(newlineLastIndexes, newLineLastIndex[0])
	}

	scopeIndexes := make([]int, 0)

	for _, scopeIndex := range allScopesIndexes {
		scopeIndexes = append(scopeIndexes, scopeIndex[1])
	}

	importRef, fileImports := checkFileExtensionAndExtractImportsAndImportRef(
		dirname,
		filename,
		string(content),
	)

	formattedFileDisplayName := strings.Split(filename, dirname)
	formattedFileName := strings.Split(filename, "/")

	return InputFile{
		PhysicalPath:       filename,
		ImportReference:    importRef,
		FileImports:        fileImports,
		ScopeLastIndexes:   scopeIndexes,
		Content:            string(content),
		ScopeIndexes:       allScopesIndexes,
		NewlineIndexes:     allNewlineIndexes,
		NewlineLastIndexes: newlineLastIndexes,
		// Gets only the file name and the extension.
		DisplayName: formattedFileDisplayName[1],
		Name:        formattedFileName[len(formattedFileName)-1],
	}
}

// Uses validates the given hazardous scope to see if this file
// is affected by vulnerabilities in other ones.
func (inputFile *InputFile) Uses(hazardousScope string) (isAffected bool) {
	isAffected = false

	if hazardousScope == "" {
		return false
	}

	for _, importOnFile := range inputFile.FileImports {
		if hazardousScope == importOnFile ||
			strings.Contains(hazardousScope, importOnFile) ||
			strings.Contains(importOnFile, hazardousScope) {
			isAffected = true
			return
		}
	}

	return
}

// FindContainingLineAndColumn finds the line of the given index
func (inputFile *InputFile) FindContainingLineAndColumn(findingIndex int) (
	lineIndex, findingColumn int) {

	lineIndex, findingColumn = binarySearchAndFixIndexes(inputFile.NewlineLastIndexes, findingIndex)
	return
}

// FindContainingDeclaration finds the containing declaration for the given index
func (inputFile *InputFile) FindContainingDeclaration(findingIndex int) string {
	insertionIndex := binarySearch(findingIndex, inputFile.ScopeLastIndexes)

	if insertionIndex > 0 {
		// TL;DR -> We have to substract 1 here to get
		// the actual index of the scope in the array

		// Because our binary search function returns the index where we
		// should insert the given element, we have to substract one
		// to find what index we should use as scope sample.
		scopeIndex := insertionIndex - 1
		scopeIndexes := inputFile.ScopeIndexes[scopeIndex]

		declaration := inputFile.Content[scopeIndexes[0]:scopeIndexes[1]]

		return strings.TrimSpace(declaration)
	}

	return ""
}

// CollectEvidenceSample returns all the data needed to save the evidence for what
// the engine have found in the source code
func (inputFile *InputFile) CollectEvidenceSample(findingIndex int) EvidenceSample {
	contextMethod := inputFile.FindContainingDeclaration(findingIndex)
	line, column := inputFile.FindContainingLineAndColumn(findingIndex)
	lineContent := ""
	lastLinesContent := ""
	nextLinesContent := ""

	evidence := EvidenceSample{}

	if contextMethod != "" {
		scope := scopeExtractor.FindStringSubmatch(contextMethod)

		if len(scope) >= 1 {
			evidence.HazardousScope = scope[len(scope)-1]
		}
	}

	// Since line is relative to the InputFile::NewlineLastIndexes array
	// If we substract one of this value we get the actual index inside
	// our indexing mechanism, so acessing the same index in the
	// InputFile->NewlineIndexes array we got both the beginning and the
	// ending index of the line.
	if line > 0 {
		lineIndex := line - 1
		if lineIndex > 0 {
			lineIndexes := inputFile.NewlineIndexes[lineIndex]
			lastLineTerminateIndexes := inputFile.NewlineIndexes[lineIndex-1]

			lineContent = inputFile.Content[lastLineTerminateIndexes[0]:lineIndexes[0]]

			if lineContent != "" {
				// If we don't have a problem tracking the line, we got the last 3 lines, and the next 3.
				lastLinesIndex := lineIndex - 3
				nextLinesIndex := lineIndex + 3

				// If we perhaps not found or something have gone wrong
				// we should only return a empty string, since it's not
				// a fatal error
				if lastLinesIndex > 0 {
					lastLinesIndexes := inputFile.NewlineIndexes[lastLinesIndex]

					lastLinesContent = inputFile.Content[lastLinesIndexes[0]:(lineIndexes[0] - 1)]
				}

				// The same for the lines before the actual line of the issue
				if nextLinesIndex < len(inputFile.NewlineIndexes) {
					nextLinesIndexes := inputFile.NewlineIndexes[nextLinesIndex]

					nextLinesContent = inputFile.Content[(lineIndexes[1] + 1):nextLinesIndexes[1]]
				}
			}
		}
	}

	preSanitizedContent := strings.ReplaceAll(lineContent, "\r", "")
	sanitizedContent := strings.ReplaceAll(preSanitizedContent, "\n", "")

	clearedLineContent := strings.ReplaceAll(sanitizedContent, " ", "")

	lineAndColumn := fmt.Sprintf("%d:%d", line, column)

	rawEvidenceHash := fmt.Sprintf("%s:%s:%s", inputFile.Name, lineAndColumn, clearedLineContent)

	evidenceHash := md5.Sum([]byte(rawEvidenceHash))

	evidence.Line = line
	evidence.Column = column
	evidence.Method = contextMethod
	evidence.BeforeContext = lastLinesContent
	evidence.AfterContext = nextLinesContent
	// Unique identifier
	evidence.UniqueHash = fmt.Sprintf("%x", evidenceHash)

	evidence.Sample = strings.TrimSpace(sanitizedContent)

	return evidence
}
