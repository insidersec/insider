package analyzers

import (
	"io/ioutil"
	"testing"

	"github.com/insidersec/insider/lexer"
	"github.com/insidersec/insider/visitor"
)

func TestExtractLibsFromPodfile(t *testing.T) {
	testFileLocation := visitor.SolvePathToTestFolder("example.podfile")
	fileContent, err := ioutil.ReadFile(testFileLocation)

	if err != nil {
		t.Fatal(err)
	}

	testFile := lexer.NewInputFile("test", testFileLocation, fileContent)

	libraries, err := ExtractLibsFromPodfile(testFile)

	if err != nil {
		t.Fatal(err)
	}

	if len(libraries) <= 0 {
		t.Fatal("Should have found libraries.")
	}

	foundPatchVersionLibrary := false
	foundMinorVersionLibrary := false
	foundLatestLibrary := false

	for _, library := range libraries {
		if library.Name == "Alamoice" {
			if library.Version == "latest" {
				foundLatestLibrary = true
				continue
			}

			t.Fatal("Fail to parse the Alamoice version")
		}

		if library.Name == "Alamofire" {
			if library.Version == "5.0.0" {
				foundPatchVersionLibrary = true
				continue
			}

			t.Fatal("Fail to parse the Alamofire version")
		}

		if library.Name == "GoogleAnalytics" {
			if library.Version == "3.1" {
				foundMinorVersionLibrary = true
				continue
			}

			t.Fatal("Fail to parse the GoogleAnalytics version")
		}
	}

	if !foundLatestLibrary {
		t.Fatal("Should have found the Alamoice library")
	}

	if !foundMinorVersionLibrary {
		t.Fatal("Should have found the GoogleAnalytics library")
	}

	if !foundPatchVersionLibrary {
		t.Fatal("Should have found the Alamofire library")
	}
}
