package rule

import (
	"regexp"

	"github.com/insidersec/insider/engine"
)

var JavascriptRules []engine.Rule = []engine.Rule{
	Rule{
		ExactMatch:    regexp.MustCompile(`(eval\(.+)(?:req\.|req\.query|req\.body|req\.param)`),
		CWE:           "CWE-94",
		AverageCVSS:   7,
		Description:   "The eval function is extremely dangerous, because if any user input that is not treated is passed to it, it may be possible to execute code remotely in the context of your application (RCE - Remote Code Executuion)",
		Recomendation: "",
	},

	Rule{
		ExactMatch:    regexp.MustCompile(`(setTimeout\(.+)(req\.|req\.query|req\.body|req\.param)`),
		CWE:           "CWE-94",
		AverageCVSS:   7,
		Description:   "The setTimeout function is very dangerous because it can interpret a string as code.",
		Recomendation: "",
	},

	Rule{
		ExactMatch:    regexp.MustCompile(`(setInterval\(.+)(req\.|req\.query|req\.body|req\.param)`),
		CWE:           "CWE-94",
		AverageCVSS:   7,
		Description:   "The setInterval function is very dangerous because it can interpret a string as code..",
		Recomendation: "",
	},

	Rule{
		ExactMatch:    regexp.MustCompile(`(require\('js-yaml'\)\.load\(|yaml\.load\()`),
		CWE:           "CWE-94",
		AverageCVSS:   7,
		Description:   "If a user-controlled data that has not been processed reaches the 'load' function, it is possible for an attacker to execute code within your application. Reference at: https://www.npmjs.com/advisories/813",
		Recomendation: "",
	},

	Rule{
		ExactMatch:    regexp.MustCompile(`(?:\[|)(?:'|")NODE_TLS_REJECT_UNAUTHORIZED(?:'|")(?:\]|)\s*=\s*(?:'|")*0(?:'|")`),
		CWE:           "CWE-295",
		AverageCVSS:   6,
		Description:   "The NODE_TLS_REJECT_UNAUTHORIZED option being disabled allows the Node.js server to accept certificates that are self-signed, allowing an attacker to bypass the TLS security layer.",
		Recomendation: "",
	},

	Rule{
		ExactMatch:    regexp.MustCompile(`SSL_VERIFYPEER\s*:\s*0`),
		CWE:           "CWE-295",
		AverageCVSS:   6,
		Description:   "The SSL_VERIFYPEER option controls the internal Node.js library, causing HTTPS requests to stop checking if a secure cryptographic tunnel has actually been established between the servers, allowing an attacker to intercept client communication in open text.",
		Recomendation: "",
	},

	Rule{
		ExactMatch:    regexp.MustCompile(`createHash\((?:'|")md5(?:'|")`),
		CWE:           "CWE-327",
		AverageCVSS:   7.4,
		Description:   "A hash algorithm used is considered weak and can cause hash collisions.",
		Recomendation: "It is always recommended to use some CHF (Cryptographic Hash Function), which is mathematically strong and not reversible. SHA512 would be the most recommended hash for storing the password and it is also important to adopt some type of Salt, so that the Hash is more secure.",
	},

	Rule{
		ExactMatch:    regexp.MustCompile(`createHash\((?:'|")sha1(?:'|")`),
		CWE:           "CWE-327",
		AverageCVSS:   7.4,
		Description:   "A hash algorithm used is considered weak and can cause hash collisions.",
		Recomendation: "It is always recommended to use some CHF (Cryptographic Hash Function), which is mathematically strong and not reversible. SHA512 would be the most recommended hash for storing the password and it is also important to adopt some type of Salt, so that the Hash is more secure.",
	},

	Rule{
		ExactMatch:    regexp.MustCompile(`handlebars\.SafeString\(`),
		CWE:           "CWE-707",
		AverageCVSS:   4,
		Description:   "Using the Handlebars SafeString function is dangerous as the data passed to it does not undergo any internal validation, so a malicious input can cause an XSS",
		Recomendation: "",
	},

	Rule{
		ExactMatch:    regexp.MustCompile(`\.createReadStream\(.*(?:req\.|req\.query|req\.body|req\.param)`),
		CWE:           "CWE-35",
		AverageCVSS:   4,
		Description:   "User data passed untreated to the 'createReadStream' function can cause a Directory Traversal attack.",
		Recomendation: "",
	},

	Rule{
		ExactMatch:    regexp.MustCompile(`\.readFile\(.*(?:req\.|req\.query|req\.body|req\.param)`),
		CWE:           "CWE-35",
		AverageCVSS:   4,
		Description:   "User data passed untreated to the 'createReadStream' function can cause a Directory Traversal attack.",
		Recomendation: "",
	},

	Rule{
		ExactMatch:    regexp.MustCompile(`\.(find|drop|create|explain|delete|count|bulk|copy).*\n*{.*\n*\$where(?:'|"|):.*(?:req\.|req\.query|req\.body|req\.param)`),
		CWE:           "CWE-943",
		AverageCVSS:   4,
		Description:   "Passing untreated parameters to queries in the database can cause an SQL injection, or even a NoSQL query injection.",
		Recomendation: "",
	},

	Rule{
		ExactMatch:    regexp.MustCompile(`res\.(write|send)\(.*(?:req\.|req\.query|req\.body|req\.param)`),
		CWE:           "CWE-79",
		AverageCVSS:   3,
		Description:   "When passing user data directly to the HTTP response headers, it is possible for an XSS to become viable.",
		Recomendation: "",
	},

	Rule{
		ExactMatch:    regexp.MustCompile(`(?:\[|)(?:'|")X-XSS-Protection(?:'|")(?:\]|)\s*=\s*(?:'|")*0(?:'|")`),
		CWE:           "CWE-693",
		AverageCVSS:   0,
		Description:   "The HTTP header X-XSS-Protection activates protection on the user's browser side to mitigate XSS-based attacks. It is important to keep it activated whenever possible.",
		Recomendation: "",
	},

	Rule{
		ExactMatch:    regexp.MustCompile(`res\.redirect\(`),
		CWE:           "CWE-601",
		AverageCVSS:   4,
		Description:   "Using the 'redirect' function can cause an Open Redirect.",
		Recomendation: "",
	},

	Rule{
		And:           []*regexp.Regexp{regexp.MustCompile(`require\((?:'|")request(?:'|")\)`), regexp.MustCompile(`request\(.*(req\.|req\.query|req\.body|req\.param)`)},
		CWE:           "CWE-79",
		AverageCVSS:   4,
		Description:   "Allowing data from user input to be used as parameters for the unhandled 'request' method could cause a Server Side Request Forgery vulnerability",
		Recomendation: "",
	},

	Rule{
		And:           []*regexp.Regexp{regexp.MustCompile(`require\((?:'|")request(?:'|")\)`), regexp.MustCompile(`\.get\(.*(req\.|req\.query|req\.body|req\.param)`)},
		CWE:           "CWE-79",
		AverageCVSS:   4,
		Description:   "Allowing data from user input to be used as parameters for the 'request.get' method without treatment could cause a Server Side Request Forgery vulnerability",
		Recomendation: "",
	},

	Rule{
		And:           []*regexp.Regexp{regexp.MustCompile(`require\((?:'|")needle(?:'|")\)`), regexp.MustCompile(`\.get\(.*(req\.|req\.query|req\.body|req\.param)`)},
		CWE:           "CWE-79",
		AverageCVSS:   4,
		Description:   "Allowing data from user input to be used as parameters for the 'needle.get' method without treatment could cause a Server Side Request Forgery vulnerability",
		Recomendation: "",
	},

	Rule{
		And:           []*regexp.Regexp{regexp.MustCompile(`require\((?:'|")child_process(?:'|")\)`), regexp.MustCompile(`\.exec\(.*(req\.|req\.query|req\.body|req\.param)`)},
		CWE:           "CWE-79",
		AverageCVSS:   4,
		Description:   "Allowing data from user input to reach the 'exec' command without treatment could cause a Remote Code Execution vulnerability",
		Recomendation: "",
	},
}
