package lexer

import (
	"regexp"
	"strings"
	"testing"
)

func TestCWE532(t *testing.T) {
	rawRegexes, err := LoadRules("android")

	if err != nil {
		t.Fatalf("Test failed: %s", err.Error())
		t.Fail()
		return
	}

	if len(rawRegexes) <= 0 {
		t.Log("Something went wrong loading the RegExp's.")
		t.Fail()
		return
	}

	testData := []string{
		"System.err.print()",
		"Log.s()",
		"Log.v()",
		"System.out.print()",
	}

	for _, rawRegex := range rawRegexes {
		if rawRegex.CWE == "CWE-532" {
			re := regexp.MustCompile(string(rawRegex.ExactMatch))
			for _, testString := range testData {

				result := re.Find([]byte(testString))
				if result == nil {
					t.Fatal("Regex failed to catch a bad code.")
				}
			}
		}
	}
}

func TestCWE312(t *testing.T) {
	rawRegexes, err := LoadRules("ios")

	if err != nil {
		t.Fatalf("Test failed: %s", err.Error())
		t.Fail()
		return
	}

	if len(rawRegexes) <= 0 {
		t.Log("Something went wrong loading the RegExp's.")
		t.Fail()
		return
	}

	testData := `
		import UIKit

		typealias JSON = [String: Any]
		typealias CompletionHandler<T: Codable> = (T?, ErrorResponse?) -> Void

		enum DefaultsManagerKeys: String {
		    case accessToken = "access_token"
		    case refreshToken = "refresh_token"
		    case transactionalPasswordCreated = "transactional_password_created"
		}

		struct Constants {
		    struct API {
		        static let acceptedLanguage = "pt_BR"
		        static let grantType = "password"
		        static let refreshToken = "refresh_token"
						static let access_token = ""
		    }
		    
		    struct ExternalServer {
		        static let serverEndpoint = "https://example-endpoint.insidersec.io"
		        static let appToken = "SDK-PWQq4Pdhtkzyt"
		    }
		    
		    struct ExternalAPI {
		        static let authKey = "201d31476ce6e4a9c801af5c4623fd7b"
		    }
		}
	`

	results := []string{}
	for _, rawRegex := range rawRegexes {
		if rawRegex.CWE == "CWE-312" {
			re := regexp.MustCompile(string(rawRegex.ExactMatch))

			result := re.Find([]byte(testData))

			if result != nil {
				results = append(results, string(result))
			}
		}
	}

	t.Logf("Found %d bad strings.", len(results))

	if len(results) <= 0 {
		t.Fatal("Regex failed to catch a bad code.")
	}
}

func TestCWE312WithXMLFile(t *testing.T) {
	rawRegexes, err := LoadRules("core")

	if err != nil {
		t.Fatalf("Test failed: %s", err.Error())
		t.Fail()
		return
	}

	if len(rawRegexes) <= 0 {
		t.Log("Something went wrong loading the RegExp's.")
		t.Fail()
		return
	}

	testData := `
		<string name="google_api_key">AIzaSyC7FlPR46a0RAsiVSX4j6X3YZnAr5Ve6OE</string>
		<string name="google_app_id">1:894280317956:android:137015e749f3988e</string>
	`

	results := []string{}
	for _, rawRegex := range rawRegexes {
		if rawRegex.CWE == "CWE-312" {
			re := regexp.MustCompile(string(rawRegex.ExactMatch))

			result := re.Find([]byte(testData))

			if result != nil {
				results = append(results, string(result))
			}
		}
	}

	t.Logf("Found %d bad strings.", len(results))

	if len(results) <= 0 {
		t.Fatal("Regex failed to catch a bad code.")
	}
}

func TestOrNotMatchShouldNotAppearInTheReport(t *testing.T) {
	rawRegexes, err := LoadRules("dotnet")

	if err != nil {
		t.Fatalf("Test failed: %s", err.Error())
		t.Fail()
		return
	}

	if len(rawRegexes) <= 0 {
		t.Log("Something went wrong loading the RegExp's.")
		t.Fail()
		return
	}

	testData := `
    PasswordValidator pwdv = new PasswordValidator
    {
      RequiredLength = 8,
      RequireNonLetterOrDigit = true,
      RequireDigit = true,
      RequireLowercase = true,
      RequireUppercase = true,
    };
`
	for _, rawRegex := range rawRegexes {
		if rawRegex.HaveNotORClause {
			re := regexp.MustCompile(rawRegex.ExactMatch)

			result := re.FindString(testData)

			if result == "" {
				t.Log("Should have found something.")
				t.Fail()
			}

			wasNotFound := true

			for _, notRule := range rawRegex.NotOr {
				re := regexp.MustCompile(notRule)

				result = re.FindString(testData)

				if result != "" {
					wasNotFound = false
				}
			}

			if !wasNotFound {
				t.Log("Rule works fine.")
				return
			}

			t.Log("Rule should not appear in the report.")
			t.Fail()
		}
	}
}

func TestOrNotMatchShouldWork(t *testing.T) {
	rawRegexes, err := LoadRules("dotnet")

	if err != nil {
		t.Fatalf("Test failed: %s", err.Error())
		t.Fail()
		return
	}

	if len(rawRegexes) <= 0 {
		t.Log("Something went wrong loading the RegExp's.")
		t.Fail()
		return
	}

	testData := `
    PasswordValidator pwdv = new PasswordValidator
    {
      RequiredLength = 8,
      RequireNonLetterOrDigit = true,
      RequireDigit = true,
    };
`
	for _, rawRegex := range rawRegexes {
		if rawRegex.HaveNotORClause && strings.Contains(rawRegex.Description, "Weak password") {
			re := regexp.MustCompile(rawRegex.ExactMatch)

			result := re.FindString(testData)

			if result == "" {
				t.Log("Should have found something.")
				t.Fail()
				return
			}

			theRuleShouldAppearInTheReport := false

			for _, notRule := range rawRegex.NotOr {
				re := regexp.MustCompile(notRule)

				result = re.FindString(testData)

				foundVulnerability := (result == "")

				if foundVulnerability {
					theRuleShouldAppearInTheReport = true
				}
			}

			if theRuleShouldAppearInTheReport {
				t.Log("Rule will appear in the report.")
				return
			}

			t.Log("Rule doesn't work.")
			t.Fail()
		}
	}
}
