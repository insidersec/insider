package analyzers

import (
	"testing"

	"inmetrics/eve/lexer"
	"inmetrics/eve/visitor"
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
		    
		    struct ExternalServer {
		        static let serverEndpoint = "https://example-endpoint.insidersec.io"
		        static let appToken = "SDK-PWQq4Pdhtkzyt"
		    }
		    
		    struct ExternalAPI {
		            static let authKey = "201d31476ce6e4a9c801af5c4623fd7b"
		    }
		}
`

	fileInput := visitor.NewInputFile(
		"testFolder",
		"testFolder/InsecureVariables.swift",
		[]byte(testData),
		// []string{"org.apache.http"},
		// []string{"android.permission.WRITE_EXTERNAL_STORAGE"},
	)

	results := AnalyzeFile(
		fileInput,
		[]lexer.Rule{
			{
				ExactMatch:  `(password\s*=\s*['|"])|(pass\s*=\s*['|"].+['|"]\s)|(username\s*=\s*['|"].+['|"])|(secret\s*=\s*['|"].+['|"])|(key\s*=\s*['|"].+['|"])|(\s*=\s*['|"]AKIA[[:alnum:]]{16})|(chave\s*=\s*['|"])|(senha\s*=\s*['|"])|(chave\s*=\s*['|"])|(\w*[tT]oken\s*=\s*['|\"])|(\w*[kK]ey\s*=\s*['|"])`,
				AverageCVSS: 7.2,
				CWE:         "CWE-312",
				Severity:    "high",
				Description: "Files may contain hardcoded sensitive informations like usernames, passwords, keys etc.",
			},
		},
	)

	// Uncomment for debug
	// logString, _ := json.Marshal(results)
	// t.Log(string(logString))

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

func TestAnalyzeFileWithNotOrRule(t *testing.T) {
	testData := `
		PasswordValidator pwdv = new PasswordValidator
		{
		    RequiredLength = 8,
		    RequireNonLetterOrDigit = true,
		    RequireDigit = true,
		};
`

	fileInput := visitor.NewInputFile(
		"testFolder",
		"testFolder/InsecurePasswordValidator.cs",
		[]byte(testData),
	)

	results := AnalyzeFile(
		fileInput,
		[]lexer.Rule{
			{
				ExactMatch:      `new\\s+PasswordValidator(?:\n*.*)*{`,
				HaveNotORClause: true,
				NotOr: []string{
					"RequireNonLetterOrDigit\\s+=\\s+true,",
					"RequireUppercase\\s+=\\s+true,",
					"RequireLowercase\\s+=\\s+true,",
					"RequireDigit\\s+=\\s+true,",
				},
			},
		},
	)

	if len(results.Findings) <= 0 {
		t.Fatal("Failed to find vulnerabilities")
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
	fileInput := visitor.NewInputFile(
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
	fileInput := visitor.NewInputFile(
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

func TestAnalyzeFileHaveNotOrRuleAndFoundNothing(t *testing.T) {
	testData := `
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <runtime>
    <assemblyBinding xmlns="urn:schemas-microsoft-com:asm.v1">
      <dependentAssembly>
        <assemblyIdentity name="System.Web.Http" publicKeyToken="31bf3856ad364e35" culture="neutral" />
        <bindingRedirect oldVersion="0.0.0.0-5.2.6.0" newVersion="5.2.6.0" />
      </dependentAssembly>
      <dependentAssembly>
        <assemblyIdentity name="System.Net.Http.Formatting" publicKeyToken="31bf3856ad364e35" culture="neutral" />
        <bindingRedirect oldVersion="0.0.0.0-5.2.6.0" newVersion="5.2.6.0" />
      </dependentAssembly>
      <dependentAssembly>
        <assemblyIdentity name="Newtonsoft.Json" publicKeyToken="30ad4fe6b2a6aeed" culture="neutral" />
        <bindingRedirect oldVersion="0.0.0.0-6.0.0.0" newVersion="6.0.0.0" />
      </dependentAssembly>
    </assemblyBinding>
  </runtime>
  <connectionStrings>
    <add name="database1" connectionString="Data Source=localhost:37017;Initial Catalog=Dev; User id=db_dativa;Password=company-name123" providerName="System.Data.SqlClient" />
    <add name="database2" connectionString="Data Source=localhost:37017;Initial Catalog=Production;User Id=db_prefaturamento_dev;Password=company-name123;" providerName="System.Data.SqlClient" />
  </connectionStrings>
</configuration>
`
	fileInput := visitor.NewInputFile(
		"testFolder",
		"testFolder/App.config",
		[]byte(testData),
	)

	rules := []lexer.Rule{
		{
			ExactMatch: "(connectionString=\".+Password=.*\")",
		},
	}

	results := AnalyzeFile(fileInput, rules)

	if len(results.Findings) > 2 {
		t.Fatal("The rule should not found more than two hardcoded credentials")
	}
}
