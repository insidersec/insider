package lexer

func AndroidRules(lang string) []Rule {
	var all []Rule

	var obj Rule
	obj.ExactMatch = `(password\s*=\s*['|"][\w\!\@\#\$\%\&\*\(\)\s]+['|"])|(pass\s*=\s*['|"][\w\!\@\#\$\%\&\*\(\)\s]+['|"]\s)|(pwd\s*=\s*['|"][\w\!\@\#\$\%\&\*\(\)\s]+['|"]\s)|(passwd\s*=\s*['|"][\w\!\@\#\$\%\&\*\(\)\s]+['|"]\s)|(senha\s*=\s*['|"][\w\!\@\#\$\%\&\*\(\)\s]+['|"])`
	obj.CWE = "CWE-312"
	obj.AverageCVSS = 6.8
	obj.Description_en = "The file contains sensitive information written directly in the code, such as usernames, passwords, keys, etc. An attacker could decompile the application and obtain the data for improper use."
	obj.Recomendation_en = "Credentials must not be stored in the Git code or repository. There are ‘Secrets Management’ solutions that can be used to store secrets or use Pipeline resources."
	all = append(all, obj)

	obj = Rule{}
	obj.ExactMatch = "\\d{2,3}\\.\\d{2,3}\\.\\d{2,3}\\.\\d{2,3}"
	obj.CWE = "CWE-312"
	obj.AverageCVSS = 6.8
	obj.Description_en = "The file contains credentials stored in the code. An attacker could decompile the application and obtain it for internal / external use."
	obj.Recomendation_en = "There are ‘Secrets Management’ solutions that can be used to store secrets."
	all = append(all, obj)

	obj = Rule{}
	obj.ExactMatch = "\\d{2,3}\\.\\d{2,3}\\.\\d{2,3}\\-\\d{1,2}"
	obj.CWE = "CWE-359"
	obj.AverageCVSS = 5.1
	obj.Description_en = "Possible personal document (CPF) written directly in the code. An attacker could decompile the application and obtain the document for misuse."
	all = append(all, obj)

	obj = Rule{}
	obj.ExactMatch = "(?mi)\\d{1,2}\\.\\d{2,3}\\.\\d{2,3}-[0-9|x]"
	obj.CWE = "CWE-359"
	obj.AverageCVSS = 5.1
	obj.Description_en = "Possible personal document (RG) written directly in the code. An attacker could decompile the application and obtain the document for misuse."
	all = append(all, obj)

	obj = Rule{}
	obj.ExactMatch = "(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"
	obj.CWE = "CWE-312"
	obj.AverageCVSS = 6.8
	obj.Description_en = "The file contains sensitive information written directly in the code, such as usernames, passwords, keys, etc. An attacker could decompile the application and obtain the data for improper use."
	obj.Recomendation_en = "Credentials must not be stored in the git code or repository, an attacker could decompile the application and obtain the credential. There are ‘Secrets Management’ solutions that can be used to store secrets or use Pipeline resources."
	all = append(all, obj)

	obj = Rule{}
	obj.ExactMatch = "(?i)aws(.{0,20})?(?-i)['\"][0-9a-zA-Z/+]{40}['\"]"
	obj.CWE = "CWE-312"
	obj.AverageCVSS = 6.8
	obj.Description_en = "The file contains sensitive information written directly in the code, such as usernames, passwords, keys, etc. An attacker could decompile the application and obtain the data for improper use."
	obj.Recomendation_en = "Credentials must not be stored in the git code or repository, an attacker could decompile the application and obtain the credential. There are ‘Secrets Management’ solutions that can be used to store secrets or use Pipeline resources."
	all = append(all, obj)

	obj = Rule{}
	obj.ExactMatch = "amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
	obj.CWE = "CWE-312"
	obj.AverageCVSS = 6.8
	obj.Description_en = "The file contains sensitive information written directly in the code, such as usernames, passwords, keys, etc. An attacker could decompile the application and obtain the data for improper use."
	obj.Recomendation_en = "Credentials must not be stored in the git code or repository, an attacker could decompile the application and obtain the credential. There are ‘Secrets Management’ solutions that can be used to store secrets or use Pipeline resources."
	all = append(all, obj)

	obj = Rule{}
	obj.ExactMatch = "(?i)api_key(.{0,20})?['\"][0-9a-zA-Z]{32,45}['\"]"
	obj.CWE = "CWE-312"
	obj.AverageCVSS = 6.8
	obj.Description_en = "Generic API key. The file contains sensitive information written directly in the code, such as usernames, passwords, keys, etc. An attacker could decompile the application and obtain the data for improper use."
	obj.Recomendation_en = "Credentials must not be stored in the git code or repository, an attacker could decompile the application and obtain the credential. There are ‘Secrets Management’ solutions that can be used to store secrets or use Pipeline resources."
	all = append(all, obj)

	return all

}
