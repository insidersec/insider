package lexer

import (
	"os"
	"path/filepath"
)

func resolveToRuleDataFolder(filename string) string {
	fullPath, _ := os.Getwd()
	return filepath.Join(fullPath, filename)
}
