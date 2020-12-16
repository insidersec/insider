package rule

import (
	"regexp"

	"github.com/insidersec/insider/engine"
)

var CsharpRules []engine.Rule = []engine.Rule{
	Rule{
		ExactMatch:  regexp.MustCompile(`\bHtml\b\.Raw\(`),
		CWE:         "CWE-79",
		AverageCVSS: 5.9,
		Description: "The application uses the potentially dangerous Html.Raw construct in conjunction with a user-supplied variable. The recommendation is to avoid using HTML assembly, but if it is extremely necessary to allow Html, we suggest the following: support only a fixed subset of Html, after the user submits content, analyze the Html and filter it in a whitelist of allowed tags and attributes. Be very careful when filtering and eliminating anything you are unsure of. https://owasp.org/www-community/attacks/xss/.",
	},

	Rule{
		Or: []*regexp.Regexp{
			regexp.MustCompile(`\s+var\s+\w+\s*=\s*"\s*\<\%\s*=\s*\w+\%\>";`),
			regexp.MustCompile(`\.innerHTML\s*:\s*.+`),
		},
		CWE:         "CWE-79",
		AverageCVSS: 5.9,
		Description: "The application appears to allow XSS through an unencrypted / unauthorized input variable. https://owasp.org/www-community/attacks/xss/.",
	},

	Rule{
		ExactMatch:  regexp.MustCompile(`<\s*customErrors\s+mode\s*=\s*"Off"\s*/>`),
		CWE:         "CWE-12",
		AverageCVSS: 2,
		Description: "The application is configured to display standard .NET errors. This can provide the attacker with useful information and should not be used in a production application. https://docs.microsoft.com/en-us/aspnet/web-forms/overview/older-versions-getting-started/deploying-web-site-projects/displaying-a-custom-error-page-cs",
	},

	Rule{
		And: []*regexp.Regexp{
			regexp.MustCompile(`using\sSystem\.Web\.Mvc;`),
			regexp.MustCompile(`using\sSystem\.Web;`),
			regexp.MustCompile(`.*\s+:\s+Controller`),
			regexp.MustCompile(`.*Server\.MapPath\(".*\+`),
		},
		CWE:         "CWE-23",
		AverageCVSS: 5.5,
		Description: "A path traversal attack (also known as directory traversal) has been detected. This attack aims to access files and directories stored outside the expected directory. The most effective way to avoid cross-file file path vulnerabilities is to avoid passing user-provided input to the file system APIs. Many application functions that do this can be rewritten to provide the same behavior more securely. https://portswigger.net/web-security/file-path-traversal",
	},

	Rule{
		ExactMatch:  regexp.MustCompile(`(?:public\sclass\s.*Controller|.*\s+:\s+Controller)(?:\n*.*)*return\s+.*".*\+`),
		CWE:         "CWE-79",
		AverageCVSS: 5.9,
		Description: "A potential Cross-Site Scripting (XSS) was found. The endpoint returns a variable from the client entry that has not been coded. Always encode untrusted input before output, regardless of validation or cleaning performed. https://docs.microsoft.com/en-us/aspnet/core/security/cross-site-scripting?view=aspnetcore-3.1",
	},

	Rule{
		Or: []*regexp.Regexp{
			regexp.MustCompile(`.*\s+new\sOdbcCommand\(.*".*\+(?:.*\n*)*.ExecuteReader\(`),
			regexp.MustCompile(`.*\s+new\sSqlCommand\(.*".*\+`),
			regexp.MustCompile(`.*\.ExecuteDataSet\(.*".*\+`),
			regexp.MustCompile(`.*\.ExecuteQuery\(@".*\+`),
		},
		CWE:         "CWE-89",
		AverageCVSS: 6.3,
		Description: "A possible SQL Injection vulnerability was found. SQL injection failures are introduced when software developers create dynamic database queries that include user-supplied input. Always validate user input by testing type, length, shape and reach. When implementing precautions against malicious entry, consider your application's architecture and deployment scenarios. Remember that programs designed to run in a secure environment can eventually be copied to an unsafe environment.https: //docs.microsoft.com/en-us/sql/relational-databases/security/sql-injection? view = sql-server-ver15",
	},

	Rule{
		ExactMatch:  regexp.MustCompile(`=\s+new\s+Random\(\);`),
		CWE:         "CWE-330",
		AverageCVSS: 3.5,
		Description: "The pseudo-random numbers generated are predictable. When the software generates predictable values in a context that requires unpredictability, it may be possible for an attacker to guess the next value that will be generated and use that guess to impersonate another user or access confidential information. To generate a cryptographically secure random number, such as the one suitable for creating a random password, use the RNGCryptoServiceProvider class or derive a class from System.Security.Cryptography.RandomNumberGenerator.https: //docs.microsoft.com/en-us/dotnet/ api / system.random? view = netframework-4.8",
	},

	Rule{
		Or: []*regexp.Regexp{
			regexp.MustCompile(`=\s+new\s+SHA1CryptoServiceProvider\(`),
			regexp.MustCompile(`:\s+new\s+MD5CryptoServiceProvider\(`),
		},
		CWE:         "CWE-326",
		AverageCVSS: 5,
		Description: "MD5 or SHA1 can cause collisions and are considered weak hashing algorithms. A weak encryption scheme may be subject to brute force attacks that have a reasonable chance of success using current methods and resources of attack. Use an encryption scheme that is currently considered strong by experts in the field. https://docs.microsoft.com/en-us/visualstudio/code-quality/ca5350?view=vs-2019 https://docs.microsoft.com/en-us/visualstudio/code-quality/ca5351?view = vs-2019",
	},

	Rule{
		Or: []*regexp.Regexp{
			regexp.MustCompile(`=\s+new\s+TripleDESCryptoServiceProvider\(`),
			regexp.MustCompile(`:\s+new\s+DESCryptoServiceProvider\(`),
			regexp.MustCompile(`:\s+TripleDES\.Create\(`),
			regexp.MustCompile(`:\s+DES\.Create\(`),
		},
		CWE:         "CWE-326",
		AverageCVSS: 5,
		Description: "DES / 3DES is considered a weak cipher for modern applications. A weak encryption scheme may be subject to brute force attacks that have a reasonable chance of success using current methods and resources of attack. Use an encryption scheme that is currently considered strong by experts in the field. Currently, NIST recommends using AES block ciphers. http://www.nist.gov/itl/fips/060205_des.cfm https://www.nist.gov/publications/advanced-encryption-standard-aes https://docs.microsoft.com/en-us/ visualstudio / code-quality / ca5351? view = vs-2019.",
	},

	Rule{
		ExactMatch:  regexp.MustCompile(`=\s+CipherMode\.ECB`),
		CWE:         "CWE-310",
		AverageCVSS: 7.1,
		Description: "This mode is not recommended because it opens the door to various security exploits. If the plain text to be encrypted contains substantial repetitions, it is possible that the cipher text will be broken one block at a time. You can also use block analysis to determine the encryption key. In addition, an active opponent can replace and exchange individual blocks without detection, which allows the blocks to be saved and inserted into the stream at other points without detection. ECB mode will produce the same result for identical blocks. The use of AES in CBC mode with an HMAC is recommended, ensuring integrity and confidentiality. https://docs.microsoft.com/en-us/visualstudio/code-quality/ca5358?view=vs-2019",
	},

	Rule{
		ExactMatch:  regexp.MustCompile(`=\s+CipherMode\.OFB`),
		CWE:         "CWE-310",
		AverageCVSS: 7.1,
		Description: "OFB mode will produce the same result for identical blocks, this mode is vulnerable to attack and can cause exposure of confidential information. An attacker could guess the encrypted message. The use of AES in CBC mode with an HMAC is recommended, ensuring integrity and confidentiality. https://docs.microsoft.com/en-us/visualstudio/code-quality/ca5358?view=vs-2019&viewFallbackFrom=vs-2019",
	},

	Rule{
		ExactMatch:  regexp.MustCompile(`new\sHttpCookie(?:.*\n*)*\.Secure\s+=\s+false`),
		CWE:         "CWE-614",
		AverageCVSS: 3,
		Description: "Secure Flag is a policy for the browser to ensure that the cookie is sent over an encrypted channel, using the SSL protocol, that is, only via HTTPS. To set the transmission of cookies using SSL for an entire application, enable it in the application's configuration file, Web.config, which resides in the application's root directory. https://docs.microsoft.com/en-us/dotnet/api/system.web.httpcookie.secure?view=netframework-4.8",
	},

	Rule{
		ExactMatch:  regexp.MustCompile(`(?:.*\s+new\sHttpCookie(?:.*\n*)*.HttpOnly\s*=\s*false|httpOnlyCookies\s*=\s*"false")`),
		CWE:         "CWE-79",
		AverageCVSS: 5.9,
		Description: "Cookies that do not have the HttpOnly flag set are available for JavaScript running on the same domain. The assigned value must be 'true' to enable the HttpOnly attribute and cannot be accessed through a client-side script; otherwise, 'false'. The default is 'false'. When a user is the target of an XSS attack, the attacker would benefit from obtaining confidential information or even progressing to a session hijack. https://docs.microsoft.com/en-us/dotnet/api/system.web.httpcookie.httponly?view=netframework-4.8",
	},

	Rule{
		ExactMatch:  regexp.MustCompile(`validateRequest\s*=\s*"false"`),
		CWE:         "CWE-20",
		AverageCVSS: 4.6,
		Description: "The validateRequest flag that provides additional protection against XSS is disabled, 'false', in the configuration file. ASP.NET examines the browser input for dangerous values when validateRequest 'true'. https://docs.microsoft.com/en-us/dotnet/api/system.web.configuration.pagessection.validaterequest?view=netframework-4.8",
	},

	Rule{
		ExactMatch:  regexp.MustCompile(`requestValidationMode\s*=\s*"(?:4.[1-9]|3.\d+|2.\d+|1.\d+|0.\d+)"`),
		CWE:         "CWE-20",
		AverageCVSS: 4.6,
		Description: "The requestValidationMode that provides additional protection against XSS is enabled only for pages, not for all HTTP requests in the configuration file. The recommended value is '4.0'. https://docs.microsoft.com/en-us/dotnet/api/system.web.configuration.httpruntimesection.requestvalidationmode?view=netframework-4.8",
	},

	Rule{
		ExactMatch:  regexp.MustCompile(`\.setPassword\("(.*?)"\)`),
		CWE:         "CWE-259",
		AverageCVSS: 5.1,
		Description: "The password setting for this API appears to be encrypted. https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password",
	},

	Rule{
		ExactMatch:  regexp.MustCompile(`new\s+PasswordValidator\(\)`),
		CWE:         "CWE-521",
		AverageCVSS: 2.3,
		Description: "The 'RequiredLength' property is missing. 'RequiredLength' must be set to a minimum value of 8.",
	},

	Rule{
		ExactMatch:  regexp.MustCompile(`new\s+PasswordValidator(?:\n*.*)*\{(?:\n*.*)*RequiredLength\s+=\s+[1-7]`),
		CWE:         "CWE-521",
		AverageCVSS: 2.3,
		Description: "The 'RequiredLength' property must be set to a minimum value of 8.",
	},

	Rule{
		ExactMatch:  regexp.MustCompile(`new\s+PasswordValidator(?:\n*.*)*{`),
		CWE:         "CWE-521",
		AverageCVSS: 2.3,
		Description: "A weak password can be guessed or forced. PasswordValidator must have at least four or five requirements to improve security (RequiredLength, RequireDigit, RequireLowercase, RequireUppercase and / or RequireNonLetterOrDigit).",
	},

	Rule{
		ExactMatch:  regexp.MustCompile(`(?:public\s+class\s+.*Controller|.*\s+:\s+Controller)(?:\n*.*)*`),
		NotOr:       []*regexp.Regexp{regexp.MustCompile(`\[ValidateAntiForgeryToken\]`)},
		CWE:         "CWE-352",
		AverageCVSS: 6.3,
		Description: "The Anti-forgery token is missing. Without this validation, an attacker could send a link to the victim and, visiting the malicious link, a web page would trigger a POST request (because it is a blind attack - the attacker does not see a response to the triggered request and does not have the use of the GET request and GET requests must not change a server state by default) for the site. The victim would not be able to recognize that an action is taken in the background, but his cookie would be sent automatically if he was authenticated on the website. This attack requires no special interaction other than visiting a website.",
	},
}
