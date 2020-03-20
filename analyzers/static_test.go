package analyzers

import (
	"testing"
	"github.com/insidersec/insider/lexer"
)

func TestAnalyzeFile(t *testing.T) {
	testData := `import UIKit

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
		    
		    struct ExternalAPI {
				        static let appToken = "SDK-PWQq4Pdhtkzyt"
				        static let serverEndpoint = "https://example-endpoint.insidersec.io"
		            static let authKey = "201d31476ce6e4a9c801af5c4623fd7b"
		    }
		}
`

	fileInput := lexer.NewInputFile(
		"testFolder",
		"testFolder/InsecureVariables.swift",
		[]byte(testData),
	)

	results := AnalyzeFile(
		fileInput,
		[]lexer.Rule{
			{
				ExactMatch: `(password\s*=\s*['|"])|(pass\s*=\s*['|"].+['|"]\s)|(username\s*=\s*['|"].+['|"])|(secret\s*=\s*['|"].+['|"])|(key\s*=\s*['|"].+['|"])|(\s*=\s*['|"]AKIA[[:alnum:]]{16})|(chave\s*=\s*['|"])|(senha\s*=\s*['|"])|(chave\s*=\s*['|"])|(\w*[tT]oken\s*=\s*['|\"])|(\w*[kK]ey\s*=\s*['|"])`,
			},
		},
	)

	if len(results.Findings) <= 0 {
		t.Fatal("Failed to find vulnerabilities")
	}

	if results.Findings[0].Line != 7 {
		t.Fatal("Failed to find the correct line for the first vulnerability.")
	}

	if results.Findings[0].Column != 12 {
		t.Fatal("Failed to find the correct column for the first vulnerability.")
	}
}

func TestAnalyzeFileAndRuleShouldWork(t *testing.T) {
	testData := `
	using System;
	using System.IO;
	using System.Web;
	using System.Linq;
	using System.Web.Mvc;
	using System.Net.Mime;

	public class TestController : Controller
	{
	    [HttpGet(""{myParam}"")]
	    public string Get(string myParam)
	    {
	        return "value " + myParam;
	    }

	    [RedirectingAction]
	    public ActionResult Download(string fileName)
	    {
	        byte[] fileBytes = File.ReadAllBytes(Server.MapPath("~/ClientDocument/") + fileName);
	        return File(fileBytes, MediaTypeNames.Application.Octet, fileName);
	    }
	}
`
	fileInput := lexer.NewInputFile(
		"testFolder",
		"testFolder/PathTraversalVulnerableController.cs",
		[]byte(testData),
	)

	rules := []lexer.Rule{
		{
			IsAndMatch: true,
			AndExpressions: []string{
				"using\\sSystem\\.Web\\.Mvc;",
				"using\\sSystem\\.Web;",
				".*\\s+:\\s+Controller",
				".*Server\\.MapPath\\(\".*\\+",
			},
		},
	}

	results := AnalyzeFile(fileInput, rules)

	if len(results.Findings) <= 0 {
		t.Fatal("Failed to find vulnerabilities")
	}
}

func TestAnalyzeFileAndRuleShouldFoundNothing(t *testing.T) {
	testData := `
	using System;
	using System.IO;
	using System.Web;
	using System.Net.Mime;

	public class Utils
	{
	    public ActionResult Download(string fileName)
	    {
	        byte[] fileBytes = File.ReadAllBytes(Server.MapPath("~/ClientDocument/") + fileName);
	        return File(fileBytes, MediaTypeNames.Application.Octet, fileName);
	    }
	}
`
	fileInput := lexer.NewInputFile(
		"testFolder",
		"testFolder/Utils.cs",
		[]byte(testData),
	)

	rules := []lexer.Rule{
		{
			IsAndMatch: true,
			AndExpressions: []string{
				"using\\sSystem\\.Web\\.Mvc;",
				"using\\sSystem\\.Web;",
				".*\\s+:\\s+Controller",
				".*Server\\.MapPath\\(\".*\\+",
			},
		},
	}

	results := AnalyzeFile(fileInput, rules)

	if len(results.Findings) > 0 {
		t.Fatal("The rule was triggered, but it should not be because it's not a Controller.")
	}
}
