package engine

import (
	"crypto/md5"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

var (
	newlineFinder = regexp.MustCompile("\x0a") // \n ASCII
	scopeFinder   = regexp.MustCompile(`(.*private.*\s*|.*public.*\s*|.*fun.*\s*)(?:{|=)`)
)

// InputFile represents a file to be analyzed
type InputFile struct {
	Name               string  // Name of file
	Content            string  // Holds the content of file
	IsDir              bool    // If InputFile is a directory or file
	DisplayName        string  // Relative path of file on directory of analysis
	PhysicalPath       string  // Absolute path of file on disk
	ScopeIndexes       [][]int // Holds information about where is a scope declaration within the file
	NewlineIndexes     [][]int // Holds information about where is the line inside the string
	NewlineLastIndexes []int   // Represents the string start index of a '\n'
	ScopeLastIndexes   []int   // Holds data about the current scope
}

// EvidenceSample holds data about where E.V.E found something
type EvidenceSample struct {
	UniqueHash string
	Line       int
	Column     int
	Sample     string
}

func NewInputFile(dir, filename string) (InputFile, error) {
	content, err := ioutil.ReadFile(filename)
	if err != nil {
		return InputFile{}, err
	}
	return NewInputFileWithContent(dir, filename, content)
}

func NewInputFileWithContent(dir, filename string, content []byte) (InputFile, error) {
	allNewlineIndexes := newlineFinder.FindAllIndex(content, -1)
	allScopesIndexes := scopeFinder.FindAllIndex(content, -1)

	newlineLastIndexes := make([]int, 0, len(allNewlineIndexes))
	for _, newLineLastIndex := range allNewlineIndexes {
		newlineLastIndexes = append(newlineLastIndexes, newLineLastIndex[0])
	}

	scopeIndexes := make([]int, 0, len(allScopesIndexes))
	for _, scopeIndex := range allScopesIndexes {
		scopeIndexes = append(scopeIndexes, scopeIndex[1])
	}

	displayName, err := filepath.Rel(dir, filename)
	if err != nil {
		return InputFile{}, err
	}

	return InputFile{
		Name:               filepath.Base(filename),
		Content:            string(content),
		DisplayName:        displayName,
		PhysicalPath:       filename,
		ScopeIndexes:       allScopesIndexes,
		NewlineIndexes:     allNewlineIndexes,
		NewlineLastIndexes: newlineLastIndexes,
		ScopeLastIndexes:   scopeIndexes,
	}, nil
}

// CollectEvidenceSample returns all the data needed to save the evidence for what
// the engine have found in the source code
func (inputFile *InputFile) CollectEvidenceSample(index int) EvidenceSample {
	line, column := inputFile.findContainingLineAndColumn(index)
	lineContent := ""

	evidence := EvidenceSample{}

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
		}
	}

	sample := strings.ReplaceAll(lineContent, "\r", "")
	sample = strings.ReplaceAll(sample, "\n", "")

	clearedLineContent := strings.ReplaceAll(sample, " ", "")
	lineAndColumn := fmt.Sprintf("%d:%d", line, column)
	evidenceHash := md5.Sum([]byte(fmt.Sprintf("%s:%s:%s", inputFile.Name, lineAndColumn, clearedLineContent)))

	evidence.Line = line
	evidence.Column = column
	evidence.UniqueHash = fmt.Sprintf("%x", evidenceHash)
	evidence.Sample = strings.TrimSpace(sample)

	return evidence
}

// findContainingLineAndColumn finds the line of the given index
func (inputFile *InputFile) findContainingLineAndColumn(index int) (int, int) {
	return binarySearchAndFixIndexes(inputFile.NewlineLastIndexes, index)
}

func binarySearch(searchIndex int, collection []int) int {
	return sort.Search(
		len(collection),
		func(index int) bool { return collection[index] >= searchIndex },
	)
}

func binarySearchAndFixIndexes(indexes []int, index int) (int, int) {
	findingLineIndex := binarySearch(index, indexes)
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
		findingColumn := index - lastNewlineIndexInTheFile

		// Since this is the slice index, + 1 should point to the real file position.
		lineIndex := findingLineIndex + 1

		return lineIndex, findingColumn
	}
	return 0, 0
}
