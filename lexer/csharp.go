package lexer

var csharp []Rule = []Rule{
	{
		ExactMatch:  "\\bHtml\\b\\.Raw\\(",
		Description: "O aplicativo usa a construção Html.Raw potencialmente perigosa em conjunto com uma variável fornecida pelo usuário.",
		CWE:         "CWE-79",
	},
	{
		IsOrMatch: true,
		OrExpressions: []string{
			"\\s+var\\s+\\w+\\s*=\\s*\"\\s*\\<\\%\\s*=\\s*\\w+\\%\\>\";",
			"\\.innerHTML\\s*=\\s*.+",
		},
		FileFilter:  ".asp & .aspx",
		Description: "O aplicativo parece permitir o XSS por meio de uma variável de entrada não codificada / não autorizada..",
	},
	{
		ExactMatch:  "<\\s*customErrors\\s+mode\\s*=\\s*\"Off\"\\s*/>",
		FileFilter:  "web.config",
		Description: "O aplicativo está configurado para exibir erros padrão do .NET. Isso pode fornecer ao invasor informações úteis e não deve ser usado em um aplicativo em produção.",
	},
	{
		IsAndMatch: true,
		AndExpressions: []string{
			"using\\sSystem\\.Web\\.Mvc;",
			"using\\sSystem\\.Web;",
			".*\\s+:\\s+Controller",
			".*Server\\.MapPath\\(\".*\\+",
		},
		Description: "Um ataque de path traversal (também conhecido como directory traversal) foi detectado. Esse ataque visa acessar arquivos e diretórios armazenados fora do diretório esperado.",
		CWE:         "CWE-23",
	},
	{
		ExactMatch:  "(?:public\\sclass\\s.*Controller|.*\\s+:\\s+Controller)(?:\n*.*)*return\\s+.*\".*\\+",
		Description: "Um XSS em potencial foi encontrado. O endpoint retorna uma variável da entrada do cliente que não foi codificada.",
		CWE:         "CWE-79",
	},
	{
		IsOrMatch: true,
		OrExpressions: []string{
			".*\\s+new\\sOdbcCommand\\(.*\".*\\+(?:.*\n*)*.ExecuteReader\\(",
			".*\\s+new\\sSqlCommand\\(.*\".*\\+",
			".*\\.ExecuteDataSet\\(.*\".*\\+",
			".*\\.ExecuteQuery\\(@\".*\\+",
		},
		Description: "As falhas de injeção de SQL são introduzidas quando os desenvolvedores de software criam consultas dinâmicas ao banco de dados que incluem entradas fornecidas pelo usuário.",
		CWE:         "CWE-89",
	},
	{
		ExactMatch:  "=\\s+new\\s+Random\\(\\);",
		Description: "Os números aleatórios gerados são previsíveis.",
		CWE:         "CWE-330",
	},
	{
		IsOrMatch: true,
		OrExpressions: []string{
			"=\\s+new\\s+SHA1CryptoServiceProvider\\(",
			"=\\s+new\\s+MD5CryptoServiceProvider\\(",
		},
		Description: "MD5 ou SHA1 podem causar colisões e são considerados algoritmos de hash fracos.",
		CWE:         "CWE-326",
	},
	{
		IsOrMatch: true,
		OrExpressions: []string{
			"=\\s+new\\s+TripleDESCryptoServiceProvider\\(",
			"=\\s+new\\s+DESCryptoServiceProvider\\(",
			"=\\s+TripleDES\\.Create\\(",
			"=\\s+DES\\.Create\\(",
		},
		Description: "O DES/3DES é considerado uma cifra fraca para aplicativos modernos. Atualmente, a NIST recomenda o uso de cifras de bloco AES (http://www.nist.gov/itl/fips/060205_des.cfm).",
		CWE:         "CWE-326",
	},
	{
		ExactMatch:    "=\\s+CipherMode\\.CBC",
		Description:   "Somente o modo CBC é suscetível ao ataque do oracle padding.",
		Recomendation: "Recomenda-se o uso de AES no modo CBC com um sufixo HMAC, garantindo integridade e confidencialidade (http://capec.mitre.org/data/definitions/463.html).",
		FileFilter:    "warning",
		CWE:           "CWE-696",
	},
	{
		ExactMatch:    "=\\s+CipherMode\\.ECB",
		Description:   "O modo ECB produzirá o mesmo resultado para blocos idênticos (ou seja: 16 bytes para AES). Um invasor pode adivinhar a mensagem criptografada.",
		Recomendation: "Recomenda-se o uso de AES no modo CBC com um HMAC, garantindo integridade e confidencialidade (http://capec.mitre.org/data/definitions/463.html).",
		CWE:           "CWE-696",
	},
	{
		ExactMatch:    "=\\s+CipherMode\\.OFB",
		Description:   "O modo OFB produzirá o mesmo resultado para blocos idênticos (ou seja: 16 bytes para AES). Um invasor pode adivinhar a mensagem criptografada.",
		Recomendation: "Recomenda-se o uso de AES no modo CBC com um HMAC, garantindo integridade e confidencialidade (http://capec.mitre.org/data/definitions/463.html).",
		CWE:           "CWE-696",
	},
	{
		ExactMatch:  "new\\sHttpCookie(?:.*\n*)*\\.Secure\\s+=\\s+false",
		Description: "A Secure Flag é uma diretiva para o navegador para garantir que o cookie não seja enviado por canal não criptografado. A desativação dele armazenará o cookie não criptografado.",
		CWE:         "CWE-315",
	},
	{
		ExactMatch:  "(?:.*\\s+new\\sHttpCookie(?:.*\n*)*.HttpOnly\\s*=\\s*false|httpOnlyCookies\\s*=\\s*\"false\")",
		Description: "Os cookies que não possuem a flag HttpOnly definida estão disponíveis para JavaScript em execução no mesmo domínio. Quando um usuário é o alvo de um ataque de XSS, em que o invasor se beneficiaria com a obtenção de informações confidenciais ou mesmo com a evolução para um ataque de seqüestro de sessão.",
		CWE:         "CWE-79",
	},
	{
		ExactMatch:  "validateRequest\\s*=\\s*\"false\"",
		Description: "A flag validateRequest que fornece proteção adicional contra o XSS está desativada no arquivo de configuração.",
	},
	{
		ExactMatch:  "requestValidationMode\\s*=\\s*\"(?:2.\\d+|1.\\d+)\"",
		Description: "O requestValidationMode que fornece proteção adicional contra o XSS é ativado apenas para páginas, não para todas as solicitações HTTP no arquivo de configuração.",
	},
	{
		ExactMatch:  "\\.setPassword\\(\"",
		Description: "A configuração da senha para esta API parece estar escrita diretamente no código.",
		CWE:         "CWE-259",
	},
	{
		ExactMatch:  "new\\s+PasswordValidator\\(\\)",
		Description: "A propriedade RequiredLength deve ser configurada com um valor mínimo de 8.",
	},
	{
		ExactMatch:  "new\\s+PasswordValidator(?:\n*.*)*\\{(?:\n*.*)*RequiredLength\\s+=\\s+[1-7]",
		Description: "A propriedade RequiredLength deve ser configurada com um valor mínimo de 8.",
	},
	{
		HaveNotORClause: true,
		ExactMatch:      "new\\s+PasswordValidator(?:\n*.*)*{",
		NotOr: []string{
			"RequireNonLetterOrDigit\\s+=\\s+true,",
			"RequireDigit\\s+=\\s+true,",
			"RequireLowercase\\s+=\\s+true,",
			"RequireUppercase\\s+=\\s+true,",
		},
		Description: "Uma Senha fraca pode ser adivinhada ou forçada. O PasswordValidator deve ter pelo menos quatro ou cinco requisitos para melhorar a segurança (RequiredLength, RequireDigit, RequireLowercase, RequireUppercase e / ou RequireNonLetterOrDigit).",
	},
	{
		HaveNotORClause: true,
		ExactMatch:      "(?:public\\s+class\\s+.*Controller|.*\\s+:\\s+Controller)(?:\n*.*)*",
		NotOr: []string{
			"\\[ValidateAntiForgeryToken\\]",
		},
		Description: "O token Anti-forgery está ausente. Sem essa validação, um invasor poderia enviar um link para a vítima e, visitando o link malicioso, uma página da Web acionaria uma solicitação POST (porque é um ataque cego - o invasor não vê uma resposta da solicitação acionada e não possui o uso da solicitação GET e as solicitações GET não devem alterar um estado no servidor por definição) para o site. A vítima não seria capaz de reconhecer que uma ação é tomada em segundo plano, mas seu cookie seria enviado automaticamente se ele fosse autenticado no site. Esse ataque não requer interação especial além de visitar um site.",
		CWE:         "CWE-352",
	},
}
