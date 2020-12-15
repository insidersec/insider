package rule

import "github.com/insidersec/insider/engine"

var JavascriptRules []engine.Rule = []engine.Rule{
	Rule{
		ExactMatch:  "(eval\\(.+)(?:req\\.|req\\.query|req\\.body|req\\.param)",
		CWE:         "CWE-94",
		AverageCVSS: 7,
		Description: "The eval function is extremely dangerous. Because if any user input is not handled correctly and passed to it, it will be possible to execute code remotely in the context of your application (RCE - Remote Code Executuion).",
	},

	Rule{
		ExactMatch:  "(?:\\[|)(?:'|\")NODE_TLS_REJECT_UNAUTHORIZED(?:'|\")(?:\\]|)\\s*=\\s*(?:'|\")*0(?:'|\")",
		CWE:         "CWE-295",
		AverageCVSS: 7.1,
		Description: "If the NODE_TLS_REJECT_UNAUTHORIZED option is disabled, the Node.js server will accept certificates that are self-signed, allowing an attacker to bypass the TLS security layer.",
	},

	Rule{
		ExactMatch:    "createHash\\((?:'|\")md5(?:'|\")",
		CWE:           "CWE-327",
		AverageCVSS:   7.1,
		Description:   "The MD5 hash algorithm that was used is considered weak. It can also cause hash collisions.",
		Recomendation: "It is always recommended to use some CHF (Cryptographic Hash Function), which is mathematically strong and not reversible. SHA512 would be the most recommended hash for storing the password and it is also important to adopt some type of Salt, so that the Hash is more secure.",
	},

	Rule{
		ExactMatch:    "createHash\\((?:'|\")sha1(?:'|\")",
		CWE:           "CWE-327",
		AverageCVSS:   7.1,
		Description:   "The SHA1 hash algorithm that was used is considered weak. It can also cause hash collisions.",
		Recomendation: "It is always recommended to use some CHF (Cryptographic Hash Function), which is mathematically strong and not reversible. SHA512 would be the most recommended hash for storing the password and it is also important to adopt some type of Salt, so that the Hash is more secure.",
	},

	Rule{
		ExactMatch:  "\\.createReadStream\\(.*(?:req\\.|req\\.query|req\\.body|req\\.param)",
		CWE:         "CWE-35",
		AverageCVSS: 5.5,
		Description: "User data passed untreated to the 'createReadStream' function can cause a Directory Traversal attack. This attack exploits the lack of security, with the attacker gaining unauthorized access to the file system.",
	},

	Rule{
		ExactMatch:  "\\.readFile\\(.*(?:req\\.|req\\.query|req\\.body|req\\.param)",
		CWE:         "CWE-35",
		AverageCVSS: 5.5,
		Description: "User data passed untreated to the 'createReadStream' function can cause a Directory Traversal attack. This attack exploits the lack of security, with the attacker gaining unauthorized access to the file system.",
	},

	Rule{
		ExactMatch:  "\\.(find|drop|create|explain|delete|count|bulk|copy).*\\n*{.*\\n*\\$where(?:'|\"|):.*(?:req\\.|req\\.query|req\\.body|req\\.param)",
		CWE:         "CWE-89",
		AverageCVSS: 6.3,
		Description: "Passing untreated parameters to queries in the database can cause an injection of SQL / NoSQL. The attacker is able to insert a custom and improper SQL statement through the data entry of an application.",
	},

	Rule{
		AndExpressions: []string{"require\\((?:'|\")request(?:'|\")\\)", "request\\(.*(req\\.|req\\.query|req\\.body|req\\.param)"},
		CWE:            "CWE-918",
		AverageCVSS:    6.5,
		Description:    "Allows user input data to be used as parameters for the 'request' method. Without proper handling, it could cause a Server Side Request Forgery vulnerability. Which is a type of exploitation in which an attacker abuses the functionality of a server, causing it to access or manipulate information in that server's domain.",
	},

	Rule{
		AndExpressions: []string{"require\\((?:'|\")request(?:'|\")\\)", "\\.get\\(.*(req\\.|req\\.query|req\\.body|req\\.param)"},
		CWE:            "CWE-918",
		AverageCVSS:    6.5,
		Description:    "Allows user input data to be used as parameters for the 'request.get' method. Without proper handling, it could cause a Server Side Request Forgery vulnerability. Which is a type of exploitation in which an attacker abuses the functionality of a server, causing it to access or manipulate information in that server's domain.",
	},
}
