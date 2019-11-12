package lexer

var javascript []Rule = []Rule{
	{
		ExactMatch:  "(eval\\(.+)(?:req\\.|req\\.query|req\\.body|req\\.param)",
		Description: "A função eval é extremamente perigosa, pois se qualquer input do usuário que não é tratado for passado para ela, poderá ser possível executar código remotamente no contexto da sua aplicação (RCE - Remote Code Executuion)",
		Severity:    "alta",
		CWE:         "CWE-94",
	},
	{
		ExactMatch:  "(?:\\[|)(?:'|\")NODE_TLS_REJECT_UNAUTHORIZED(?:'|\")(?:\\]|)\\s*=\\s*(?:'|\")*0(?:'|\")",
		Description: "A opção NODE_TLS_REJECT_UNAUTHORIZED estar desabilitada permite que o servidor Node.js aceite certificados que são auto assinados, permitindo um atacante ignorar a camada de segurança do TLS.",
		Severity:    "alta",
		CWE:         "CWE-295",
	},
	{
		ExactMatch:    "createHash\\((?:'|\")md5(?:'|\")",
		Description:   "Um algoritmo de hash utilizado é considerado fraco e pode causar colisões de hash.",
		Recomendation: "É sempre recomendado utilizar alguma CHF (Cryptographic Hash Function), que é matematicamente forte e não reversível. SHA512 seria a hash mais recomendada para armazenamento da senha e também é importante adotar algum tipo de Salt, para que a Hash fique mais segura.",
		Severity:      "alta",
		CWE:           "CWE-327",
	},
	{
		ExactMatch:    "createHash\\((?:'|\")sha1(?:'|\")",
		Description:   "Um algoritmo de hash utilizado é considerado fraco e pode causar colisões de hash.",
		Recomendation: "É sempre recomendado utilizar alguma CHF (Cryptographic Hash Function), que é matematicamente forte e não reversível. SHA512 seria a hash mais recomendada para armazenamento da senha e também é importante adotar algum tipo de Salt, para que a Hash fique mais segura.",
		Severity:      "alta",
		CWE:           "CWE-327",
	},
	{
		ExactMatch:  "\\.createReadStream\\(.*req\\.|req\\.query|req\\.body|req\\.param",
		Description: "Dados de usuários passados sem tratamento para a função 'createReadStream' pode causar um ataque de Directory Traversal.",
		Severity:    "média",
		CWE:         "CWE-35",
	},
	{
		ExactMatch:  "\\.readFile\\(.*req\\.|req\\.query|req\\.body|req\\.param",
		Description: "Dados de usuários passados sem tratamento para a função 'readFile' pode causar um ataque de Directory Traversal.",
		Severity:    "média",
		CWE:         "CWE-35",
	},
	{
		ExactMatch:  "\\.(find|drop|create|explain|delete|count|bulk|copy).*\\n*{.*\\n*\\$where(?:'|\"|):.*(?:req\\.|req\\.query|req\\.body|req\\.param)",
		Description: "Passar parametros sem tratamento para queries no banco de dados pode causar uma injeção de SQL, ou até mesmo uma injeção de query NoSQL.",
		Severity:    "média",
		CWE:         "CWE-943",
	},
	{
		IsAndMatch: true,
		AndExpressions: []string{
			"require\\((?:'|\")request(?:'|\")\\)",
			"request\\(.*(req\\.|req\\.query|req\\.body|req\\.param)",
		},
		Description: "Permitir que dados vindos da entrada do usuário sejam usados como parametros para o método 'request' sem tratamento pode causar uma vulnerabilidade do tipo Server Side Request Forgery",
		Severity:    "média",
		CWE:         "CWE-79",
	},
	{
		IsAndMatch: true,
		AndExpressions: []string{
			"require\\((?:'|\")request(?:'|\")\\)",
			"\\.get\\(.*(req\\.|req\\.query|req\\.body|req\\.param)",
		},
		Description: "Permitir que dados vindos da entrada do usuário sejam usados como parametros para o método 'request.get' sem tratamento pode causar uma vulnerabilidade do tipo Server Side Request Forgery",
		Severity:    "média",
		CWE:         "CWE-79",
	},
}
