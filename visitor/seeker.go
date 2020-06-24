package visitor

import (
	"os"
	"path/filepath"
	"strings"
)

var decompiledStructureFiles = []string{
	"libs.e",
	"header.e",
	"Info.plist",
	"dynsymtable.e",
}

func findDecompiledStructures(path string) (isDecompiled bool) {
	isDecompiled = false
	for _, structuralFile := range decompiledStructureFiles {
		if strings.Contains(path, structuralFile) {
			isDecompiled = true
			continue
		}
	}
	return
}

// ClassifySample searches for specific files inside the sample
// to distinguish between iOS decompiled binaries and source code
func ClassifySample(dirname string) (string, error) {
	results := make([]bool, 0)
	err := filepath.Walk(dirname, func(path string, info os.FileInfo, err error) error {
		if info.IsDir() && path != dirname {
			// There should not be any folder inside a decompiled app
			results = append(results, false)
			return filepath.SkipDir
		} else if path == dirname {
			return nil
		}

		result := findDecompiledStructures(path)
		results = append(results, result)
		return nil
	})

	if err != nil {
		return "", err
	}

	for _, result := range results {
		if !result {
			return "source", nil
		}
	}

	return "binary", nil
}
