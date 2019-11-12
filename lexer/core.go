package lexer

var core []Rule = []Rule{
	{
		IsOrMatch:  true,
		ExactMatch: "(key\\s*=\\s*['|\"]\\w+['|\"])|password\\s*=\\s*['|\"]\\w+['|\"])|(pass\\s*=\\s*['|\"]\\w+['|\"]\\s)|(pwd\\s*=\\s*['|\"]\\w+['|\"]\\s)|(passwd\\s*=\\s*['|\"]\\w+['|\"]\\s)|(username\\s*=\\s*['|\"]\\w+['|\"])|(secret\\s*=\\s*['|\"]\\w+['|\"])|(chave\\s*=\\s*['|\"]\\w+['|\"])|(senha\\s*=\\s*['|\"]\\w+['|\"])|(chave\\s*=\\s*['|\"]\\w+['|\"])|(\\w*[tT]oken\\s*=\\s*['|\"]\\w+['|\"])|(\\w*[aA][uU][tT][hH]\\w*\\s*=\\s*['|\"]\\w+['|\"])",
		NotOr: []string{
			"public.*[tT]oken",
			"public.*[kK]ey",
		},
		Description:   "Arquivo contém informação sensível escrita diretamente, como nomes de usuário, senhas, chaves , etc.",
		Recomendation: "Credenciais não devem ser armazenadas no código ou repositório GIT, um atacante poderia descompilar a aplicação e obter a credencial. Existem soluções de ‘Secrets Management’ que podem ser utilizados para armazenar segredos ou utilizar recursos da Pipeline.",
		Severity:      "alta",
		CWE:           "CWE-312",
	},
	{
		ExactMatch:    "\\d{2,3}\\.\\d{2,3}\\.\\d{2,3}\\.\\d{2,3}",
		Description:   "Credenciais não devem ser armazenadas no código, um atacante poderia descompilar a aplicação e obter a credencial.",
		Recomendation: "Existem soluções de ‘Secrets Management’ que podem ser utilizados para armazenar segredos.",
		Severity:      "info",
		CWE:           "CWE-200",
	},
	{
		ExactMatch:  "\\d{2,3}\\.\\d{2,3}\\.\\d{2,3}\\-\\d{1,2}",
		Description: "Possível documento pessoal hardcoded (CPF)",
		Severity:    "info",
		CWE:         "CWE-359",
	},
	{
		ExactMatch:  "(?mi)\\d{1,2}\\.\\d{2,3}\\.\\d{2,3}-[0-9|x]",
		Description: "Possível documento pessoal hardcoded (RG)",
		Severity:    "info",
		CWE:         "CWE-359",
	},
	{
		Description:   "Arquivo contém informação sensível escrita diretamente, como nomes de usuário, senhas, chaves , etc.",
		Recomendation: "Credenciais não devem ser armazenadas no código ou repositório GIT, um atacante poderia descompilar a aplicação e obter a credencial. Existem soluções de ‘Secrets Management’ que podem ser utilizados para armazenar segredos ou utilizar recursos da Pipeline.",
		ExactMatch:    "(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
		Severity:      "alta",
		CWE:           "CWE-312",
	},
	{
		Description:   "Arquivo contém informação sensível escrita diretamente, como nomes de usuário, senhas, chaves , etc.",
		Recomendation: "Credenciais não devem ser armazenadas no código ou repositório GIT, um atacante poderia descompilar a aplicação e obter a credencial. Existem soluções de ‘Secrets Management’ que podem ser utilizados para armazenar segredos ou utilizar recursos da Pipeline.",
		ExactMatch:    "(?i)aws(.{0,20})?(?-i)['\"][0-9a-zA-Z/+]{40}['\"]",
		Severity:      "alta",
		CWE:           "CWE-312",
	},
	{
		Description:   "Arquivo contém informação sensível escrita diretamente, como nomes de usuário, senhas, chaves , etc.",
		Recomendation: "Credenciais não devem ser armazenadas no código ou repositório GIT, um atacante poderia descompilar a aplicação e obter a credencial. Existem soluções de ‘Secrets Management’ que podem ser utilizados para armazenar segredos ou utilizar recursos da Pipeline.",
		ExactMatch:    "amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
		Severity:      "alta",
		CWE:           "CWE-312",
	},
	{
		Description:   "Chave de API generica. Arquivo contém informação sensível escrita diretamente, como nomes de usuário, senhas, chaves , etc.",
		Recomendation: "Credenciais não devem ser armazenadas no código ou repositório GIT, um atacante poderia descompilar a aplicação e obter a credencial. Existem soluções de ‘Secrets Management’ que podem ser utilizados para armazenar segredos ou utilizar recursos da Pipeline.",
		ExactMatch:    "(?i)api_key(.{0,20})?['\"][0-9a-zA-Z]{32,45}['\"]",
		Severity:      "alta",
		CWE:           "CWE-312",
	},
}
