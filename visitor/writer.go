package visitor

import (
	"os"
	"path/filepath"
)

func resolvePath(prefix string, path ...string) string {
	pathPrefix := os.Getenv("GOPATH")

	fullPath := []string{pathPrefix}
	fullPath = append(fullPath, prefix)
	fullPath = append(fullPath, path...)

	return filepath.Join(fullPath...)
}

// SolvePathToTmpFolder resolves the path
// to the physical path of the tmp/
// inside the project
func SolvePathToTmpFolder(path ...string) string {
	projectPrefix := "src/inmetrics/eve/tmp"
	return resolvePath(projectPrefix, path...)
}

// SolvePathToTestFolder resolves the path
// to the physical path of the test/
// inside the project
func SolvePathToTestFolder(path ...string) string {
	prefix := "src/inmetrics/eve/test"
	return resolvePath(prefix, path...)
}
