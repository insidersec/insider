package visitor

import (
	"errors"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/insidersec/insider/connectors"
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
	projectPrefix := "src/inmetrics/insider/tmp"
	return resolvePath(projectPrefix, path...)
}

// ReceiveSample try to download the given file
// from the configured S3 bucket, retrying two times
// in 4 seconds.
func ReceiveSample(name string) (filename string, shouldExtractHashes bool, err error) {
	filename = SolvePathToTmpFolder(name)
	storageConnector := connectors.NewStorageConnector()

	file, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE, 0744)

	if err != nil {
		return
	}

	defer file.Close()

	var fileOnS3 string
	for i := 0; i < 2; i++ {
		fileOnS3, shouldExtractHashes, err = storageConnector.RetrieveObjectFromStorage(
			filename,
			file,
		)

		if err != nil {
			log.Println("Error downloading sample, retrying in 2 seconds...")
			time.Sleep(2 * time.Second)
			continue
		} else {
			break
		}
	}

	if fileOnS3 == "" {
		err = errors.New("error downloading sample, please try again")
		return
	}

	return
}
