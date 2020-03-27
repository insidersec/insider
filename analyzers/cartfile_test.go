package analyzers

import (
	"io/ioutil"
	"testing"
	"path/filepath"
	"github.com/insidersec/insider/lexer"
)

func TestExtractLibsFromCartfile(t *testing.T) {
	testFileLocation := filepath.FromSlash("testdata/example.cartfile")c
	fileContent, err := ioutil.ReadFile(filepath.Clean(testFileLocation))

	if err != nil {
		t.Fatal(err)
	}

	testFile := lexer.NewInputFile("test", testFileLocation, fileContent)

	libraries, err := ExtractLibsFromCartfile(testFile)

	if err != nil {
		t.Fatal(err)
	}

	if len(libraries) <= 0 {
		t.Fatal("Should have found libraries.")
	}

	foundExternalLib := false
	foundPrivateLib := false
	foundLocalLib := false
	foundLatestLib := false

	for _, library := range libraries {
		if library.Name == "Mantle/Mantle" {
			if library.Version == "1.0" && library.Source == "github" {
				foundExternalLib = true
				continue
			}

			t.Fatal("Problems parsing the Mantle/Mantle version")
		}

		if library.Name == "https://enterprise.local/desktop/git-error-translations2.git" {
			if library.Version == "development" && library.Source == "git" {
				foundPrivateLib = true
				continue
			}

			t.Fatal("Problems parsing the git-error-translations2.git version")
		}

		if library.Name == "relative/path/MyFramework.json" {
			if library.Version == "2.33" && library.Source == "binary" {
				foundLocalLib = true
				continue
			}

			t.Fatal("Problems parsing the MyFramework.json version")
		}

		if library.Name == "https://enterprise.local/ghe/desktop/git-error-translations" {
			if library.Version == "latest" && library.Source == "github" {
				foundLatestLib = true
				continue
			}

			t.Fatal("Problems parsing the git-error-translations version")
		}
	}

	if !foundExternalLib {
		t.Fatal("Failed to find external library Mantle/Mantle from GitHub")
	}

	if !foundLocalLib {
		t.Fatal("Failed to find local binary library MyFramework.json")
	}

	if !foundPrivateLib {
		t.Fatal("Failed to find private library git-error-translations2 from GitHub Enterprise Server")
	}

	if !foundLatestLib {
		t.Fatal("Failed to find the library with latest version from GitHub Enterprise Server")
	}
}
