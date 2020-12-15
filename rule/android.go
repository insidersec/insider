package rule

import "github.com/insidersec/insider/engine"

var AndroidRules []engine.Rule = []engine.Rule{
	Rule{
		ExactMatch:    `(password\s*=\s*['|"][\w\!\@\#\$\%\&\*\(\)\s]+['|"])|(pass\s*=\s*['|"][\w\!\@\#\$\%\&\*\(\)\s]+['|"]\s)|(pwd\s*=\s*['|"][\w\!\@\#\$\%\&\*\(\)\s]+['|"]\s)|(passwd\s*=\s*['|"][\w\!\@\#\$\%\&\*\(\)\s]+['|"]\s)|(senha\s*=\s*['|"][\w\!\@\#\$\%\&\*\(\)\s]+['|"])`,
		CWE:           "CWE-312",
		AverageCVSS:   6.8,
		Description:   "The file contains sensitive information written directly in the code, such as usernames, passwords, keys, etc. An attacker could decompile the application and obtain the data for improper use.",
		Recomendation: "Credentials must not be stored in the Git code or repository. There are ‘Secrets Management’ solutions that can be used to store secrets or use Pipeline resources.",
	},
	Rule{
		ExactMatch:    "\\d{2,3}\\.\\d{2,3}\\.\\d{2,3}\\.\\d{2,3}",
		CWE:           "CWE-312",
		AverageCVSS:   6.8,
		Description:   "The file contains credentials stored in the code. An attacker could decompile the application and obtain it for internal / external use.",
		Recomendation: "There are ‘Secrets Management’ solutions that can be used to store secrets.",
	},
	Rule{
		ExactMatch:  "\\d{2,3}\\.\\d{2,3}\\.\\d{2,3}\\-\\d{1,2}",
		CWE:         "CWE-359",
		AverageCVSS: 5.1,
		Description: "Possible personal document (CPF) written directly in the code. An attacker could decompile the application and obtain the document for misuse.",
	},

	Rule{
		ExactMatch:  "(?mi)\\d{1,2}\\.\\d{2,3}\\.\\d{2,3}-[0-9|x]",
		CWE:         "CWE-359",
		AverageCVSS: 5.1,
		Description: "Possible personal document (RG) written directly in the code. An attacker could decompile the application and obtain the document for misuse.",
	},

	Rule{
		ExactMatch:    "(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
		CWE:           "CWE-312",
		AverageCVSS:   6.8,
		Description:   "The file contains sensitive information written directly in the code, such as usernames, passwords, keys, etc. An attacker could decompile the application and obtain the data for improper use.",
		Recomendation: "Credentials must not be stored in the git code or repository, an attacker could decompile the application and obtain the credential. There are ‘Secrets Management’ solutions that can be used to store secrets or use Pipeline resources.",
	},
	Rule{
		ExactMatch:    "(?i)aws(.{0,20})?(?-i)['\"][0-9a-zA-Z/+]{40}['\"]",
		CWE:           "CWE-312",
		AverageCVSS:   6.8,
		Description:   "The file contains sensitive information written directly in the code, such as usernames, passwords, keys, etc. An attacker could decompile the application and obtain the data for improper use.",
		Recomendation: "Credentials must not be stored in the git code or repository, an attacker could decompile the application and obtain the credential. There are ‘Secrets Management’ solutions that can be used to store secrets or use Pipeline resources.",
	},
	Rule{
		ExactMatch:    "amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
		CWE:           "CWE-312",
		AverageCVSS:   6.8,
		Description:   "The file contains sensitive information written directly in the code, such as usernames, passwords, keys, etc. An attacker could decompile the application and obtain the data for improper use.",
		Recomendation: "Credentials must not be stored in the git code or repository, an attacker could decompile the application and obtain the credential. There are ‘Secrets Management’ solutions that can be used to store secrets or use Pipeline resources.",
	},
	Rule{
		ExactMatch:    "(?i)api_key(.{0,20})?['\"][0-9a-zA-Z]{32,45}['\"]",
		CWE:           "CWE-312",
		AverageCVSS:   6.8,
		Description:   "Generic API key. The file contains sensitive information written directly in the code, such as usernames, passwords, keys, etc. An attacker could decompile the application and obtain the data for improper use.",
		Recomendation: "Credentials must not be stored in the git code or repository, an attacker could decompile the application and obtain the credential. There are ‘Secrets Management’ solutions that can be used to store secrets or use Pipeline resources.",
	},
}
