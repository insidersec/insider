package analyzers

import (
	"os"
	"path/filepath"

	"github.com/insidersec/insider/models/reports"
)

// IsLibraryUsed self-explained
func IsLibraryUsed(libraries []reports.Library, item string) bool {
	for _, library := range libraries {
		if library.Name == item {
			return true
		}
	}

	return false
}

// IsUsed self-explained
func IsUsed(collection []string, item string) bool {
	for _, itemInCollection := range collection {
		if itemInCollection == item {
			return true
		}
	}

	return false
}

// GetUnpackedAppSize self-explained
func GetUnpackedAppSize(path string) (int, error) {
	var size int64

	err := filepath.Walk(path, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			size += info.Size()
		}
		return err
	})

	// Transform the Size to MB
	//megabytes := int(float64(size) / (1024 * 1024))
	megabytes := int(float64(size))

	return megabytes, err
}
