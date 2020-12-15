package engine

import (
	"os"
	"path/filepath"
)

// FinderFunc func to be used to find files in directory
type FinderFunc func(path string) bool

// FindInputFiles searches for filenames who the given find returns true
// if includeDirs is set to true, the directory will be included in the list of input files
func FindInputFiles(dir string, includeDirs bool, find FinderFunc) ([]InputFile, error) {
	files := make([]InputFile, 0)
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if find(path) {
			if info.IsDir() {
				if includeDirs {
					file, err := NewInputFileWithContent(dir, path, []byte{})
					if err != nil {
						return err
					}
					file.IsDir = true
					files = append(files, file)
					return nil
				}
				return nil
			}

			file, err := NewInputFile(dir, path)
			if err != nil {
				return err
			}

			files = append(files, file)
			return nil
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	return files, nil
}
