package visitor

import (
	"testing"
)

func TestFindDecompiledStructuresShouldMatch(t *testing.T) {
	paths := []string{
		"/tmp/libs.e",
		"/tmp/header.e",
		"/tmp/Info.plist",
		"/tmp/dynsymtable.e",
	}

	results := make([]bool, 0)

	for _, path := range paths {
		results = append(results, findDecompiledStructures(path))
	}

	for _, result := range results {
		if !result {
			t.Fatal("Should have returned true")
		}
	}
}

func TestClassifySampleShouldFindABinarySample(t *testing.T) {
	testPath := SolvePathToTestFolder("walleSample")
	sampleCategory, err := ClassifySample(testPath)

	if err != nil {
		t.Fatal(err.Error())
	}

	if sampleCategory != "binary" {
		t.Fatal("Should have classified this sample as binary")
	}
}
