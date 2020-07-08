package visitor

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// ArchiveEvidence checks for the corresponding evidence folder for a given
// analysis, and copies the file to there.
func ArchiveEvidence(correlationID, filename string) (evidencePath string, err error) {
	archiveName := fmt.Sprintf("%s-evidences", correlationID)
	archivePhysicalPath := SolvePathToTmpFolder(archiveName)

	// If the folder does not exists yet, creates it.
	if _, err = os.Stat(archivePhysicalPath); os.IsNotExist(err) {
		if err := os.Mkdir(archivePhysicalPath, 0777); err != nil {
			return "", err
		}

	} else if err != nil {
		return
	}

	// We should remove the rest of the path to make sure we do not bug down the copy
	fileOriginalPath := strings.Split(filename, "tmp/")[1]
	filenameWithoutPath := strings.ReplaceAll(fileOriginalPath, "/", ".")

	// So now we have a file with the same name inside the evidences folder
	evidencePath = filepath.Join(archivePhysicalPath, filenameWithoutPath)

	// I know that a lot of file creation methods are using this permissive permission
	// but we have to optmize it anyway :/
	// but the #1 priority now is no crashes in the engine
	// @TODO checks a better file permission scheme
	evidenceFile, err := os.OpenFile(evidencePath, os.O_CREATE|os.O_WRONLY, 0666)

	if err != nil {
		return
	}

	originalFile, err := os.Open(filename)

	if err != nil {
		return
	}

	defer evidenceFile.Close()
	defer originalFile.Close()

	_, err = io.Copy(evidenceFile, originalFile)

	if err != nil {
		return
	}

	evidencePath = strings.Split(evidencePath, "tmp/")[1]

	return
}
