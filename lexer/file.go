package lexer

import (
	"regexp"
	"sort"
	"strings"
	"github.com/insidersec/insider/models"
)

var scopeFinder *regexp.Regexp
var newlineFinder *regexp.Regexp

// InputFile represents a file to be analyzed
type InputFile struct {
	Name         string
	Content      string
	IsDir        bool
	Libraries    []models.Library
	Permissions  []string
	DisplayName  string
	PhysicalPath string

	// Indexes for file reference
	// ScopeIndexes holds information about where is a scope declaration within the file
	// NewlineIndexes holds information about where is the line inside the string
	ScopeIndexes   [][]int
	NewlineIndexes [][]int
	// NewlineLastIndexes represents the string start index of a '\n'
	// ScopeLastIndexes holds data about the current scope
	NewlineLastIndexes []int
	ScopeLastIndexes   []int
}

// EvidenceSample holds data about where E.V.E found something
type EvidenceSample struct {
	Line          int
	Column        int
	Method        string
	Sample        string
	AfterContext  string
	BeforeContext string
}

func init() {
	newlineFinder = regexp.MustCompile("\x0a")
	scopeFinder = regexp.MustCompile(`(.*private.*\s*|.*public.*\s*|.*fun.*\s*)(?:{|=)`)
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

	formattedFileDisplayName := strings.Split(filename, dirname)
	formattedFileName := strings.Split(filename, "/")

	return InputFile{
		PhysicalPath:       filename,
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

// FindContainingLineAndColumn finds the line of the given index
func (inputFile *InputFile) FindContainingLineAndColumn(findingIndex int) (lineIndex, findingColumn int) {

	lineIndex, findingColumn = binarySearchAndFixIndexes(inputFile.NewlineLastIndexes, findingIndex)
	return
}

// FindContainingDeclaration finds the containing declaration for the given index
func (inputFile *InputFile) FindContainingDeclaration(findingIndex int) string {
	insertionIndex := binarySearch(findingIndex, inputFile.ScopeLastIndexes)

	if insertionIndex > 0 {
		// Because our binary search function returns the index where we
		// should insert the given element, we have to substract one
		// to find what index we should use as scope sample.

		// TL;DR -> We have to substract 1 here to get
		// the actual index of the scope in the array
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
	headerContent := ""
	lastLinesContent := ""
	nextLinesContent := ""

	// Since line is relative to the InputFile::NewlineLastIndexes array
	// If we substract one of this value we get the actual index inside
	// our indexing mechanism, so acessing the same index in the
	// InputFile::NewlineIndexes array we got both the beginning and the
	// ending index of the line.
	if line > 0 {
		lineIndex := line - 1
		if lineIndex > 0 {
			lineIndexes := inputFile.NewlineIndexes[lineIndex]

			lineContent = inputFile.Content[lineIndexes[0]:lineIndexes[1]]

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

	evidence := EvidenceSample{
		Line:          line,
		Column:        column,
		Method:        contextMethod,
		BeforeContext: lastLinesContent,
		AfterContext:  nextLinesContent,
	}

	if evidence.Method != "" {
		content := strings.ReplaceAll(evidence.Method, "\r", "")
		headerContent = strings.ReplaceAll(content, "\n", "")
	} else {
		headerContent = ""
	}

	evidence.Sample = headerContent

	return evidence
}
