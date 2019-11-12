package lexer

var android []Rule = []Rule{
	{
		ExactMatch:    "Cipher\\.getInstance\\(\\s*\".+/ECB/.+\\)",
		Description:   "A aplicação usa ECB como 'block mode' do algoritmo de criptografia. ECB é considerado um algoritmo criptográfico fraco, pois resulta na mesma cifra para blocos idênticos de texto simples.",
		Recomendation: "É sempre recomendado utilizar alguma CHF (Cryptographic Hash Function), que é matematicamente forte e não reversível. SHA512 seria a hash mais recomendada para armazenamento da senha e também é importante adotar algum tipo de Salt, para que a Hash fique mais segura.",
		Severity:      "alta",
		CWE:           "CWE-327",
	},
	{
		ExactMatch:    "Cipher\\.getInstance\\(\\s*\".+/ECB/.+\\)",
		Severity:      "alta",
		Description:   "DES é um algoritmo de hash considerado fraco e pode causar colisões de hash.",
		Recomendation: "É sempre recomendado utilizar alguma CHF (Cryptographic Hash Function), que é matematicamente forte e não reversível. SHA512 seria a hash mais recomendada para armazenamento da senha e também é importante adotar algum tipo de Salt, para que a Hash fique mais segura.",
		CWE:           "CWE-327",
	},
	{
		ExactMatch:    "Cipher\\.getInstance\\(\\s*\"AES/.+/.+\\)",
		Severity:      "média",
		Description:   "Uso de criptografia fraca para armazenamento de informação sensível.",
		Recomendation: "É sempre recomendado utilizar alguma CHF (Cryptographic Hash Function), que é matematicamente forte e não reversível. SHA512 seria a hash mais recomendada para armazenamento da senha e também é importante adotar algum tipo de Salt, para que a Hash fique mais segura.",
		CWE:           "CWE-326",
	},
	{
		ExactMatch:    "Cipher\\.getInstance\\(\\s*\".+/GCM/.+\\)",
		Severity:      "baixa",
		Description:   "A aplicação usa GCM como 'block mode' do algoritmo de criptografia. GCM é considerado um algoritmo criptográfico fraco, pois como ele somente incrementa em 1 o valor do IV, é facil prever as chaves por bloco com um numero suficiente de mensagens criptografadas com a mesma chave e/ou IV.",
		Recomendation: "É sempre recomendado utilizar CBC (Cipher Block Chaining) pois ele oferece mais segurança de que o IV sera bem utilizado e também é importante adotar algum tipo de 'salt', para que a hash fique mais segura.",
		CWE:           "CWE-326",
	},
	{
		ExactMatch:  "Cipher\\.getInstance\\(\\s*\"RSA/.+/NoPadding",
		Severity:    "alta",
		Description: "Essa aplicação utiliza criptografia RSA sem OAEP Padding. O padding previne alguns tipos de ataque, que utilizariam a falta de padding como vetor de ataque.",
		CWE:         "CWE-780",
	},
	{
		IsAndMatch: true,
		AndExpressions: []string{
			"javax\\.net\\.ssl",
			"TrustAllSSLSocket-Factory|AllTrustSSLSocketFactory|NonValidatingSSLSocketFactory|net\\.SSLCertificateSocketFactory|ALLOW_ALL_HOSTNAME_VERIFIER|\\.setDefaultHostnameVerifier\\(|NullHostnameVerifier\\(",
		},
		Severity:    "alta",
		Description: "Implementação insegura de SSL. Confiar em qualquer certificado ou aceitar certificados auto-assinados podem causar uma séria brecha de segurança, tornando a aplicação vulnerável a ataques MITM (Man In The Middle).",
		CWE:         "CWE-295",
	},
	{
		IsAndMatch: true,
		AndExpressions: []string{
			"\\.loadUrl\\(.*getExternalStorageDirectory\\(",
			"webkit\\.WebView",
		},
		Description: "A WebView carrega arquivos do armazenamento externo. Arquivos do armazenamento externo podem ser modificados por qualquer aplicação.",
		Severity:    "alta",
		CWE:         "CWE-919",
	},
	{
		ExactMatch:    "getInstance(\"md4\")|getInstance(\"rc2\")|getInstance(\"rc4\")|getInstance(\"RC4\")|getInstance(\"RC2\")|getInstance(\"MD4\")",
		Description:   "Um algoritmo de hash utilizado é considerado fraco e pode causar colisões de hash.",
		Recomendation: "É sempre recomendado utilizar alguma CHF (Cryptographic Hash Function), que é matematicamente forte e não reversível. SHA512 seria a hash mais recomendada para armazenamento da senha e também é importante adotar algum tipo de Salt, para que a Hash fique mais segura.",
		Severity:      "alta",
		CWE:           "CWE-327",
	},
	{
		ExactMatch:    "MessageDigest\\.getInstance\\(\"*MD5\"*\\)|MessageDigest\\.getInstance\\(\"*md5\"*\\)|DigestUtils\\.md5\\(",
		Description:   "MD5 é um algoritmo de hash considerado fraco e pode causar colisões de hash.",
		Recomendation: "É sempre recomendado utilizar alguma CHF (Cryptographic Hash Function), que é matematicamente forte e não reversível. SHA512 seria a hash mais recomendada para armazenamento da senha e também é importante adotar algum tipo de Salt, para que a Hash fique mais segura.",
		Severity:      "alta",
		CWE:           "CWE-327",
	},
	{
		ExactMatch:    "MessageDigest\\.getInstance\\(\"*SHA-1\"*\\)|MessageDigest\\.getInstance\\(\"*sha-1\"*\\)|DigestUtils\\.sha\\(",
		Description:   "SHA-1 é um algoritmo de hash considerado fraco e pode causar colisões de hash.",
		Recomendation: "É sempre recomendado utilizar alguma CHF (Cryptographic Hash Function), que é matematicamente forte e não reversível. SHA512 seria a hash mais recomendada para armazenamento da senha e também é importante adotar algum tipo de Salt, para que a Hash fique mais segura.",
		Severity:      "alta",
		CWE:           "CWE-327",
	},
	{
		ExactMatch:    "java\\.util\\.Random",
		Description:   "A aplicação utiliza um gerador de números aleatórios previsível, portanto inseguro.",
		Recomendation: "Para uma implementação melhor seria utilizar o pacote java.util.SecureRandom",
		Severity:      "alta",
		CWE:           "CWE-330",
	},
	{
		ExactMatch:  "setFilterTouchesWhenObscured\\(true\\)",
		Description: "A aplicação tem a capacidade de previnir ataques do tipo tapjacking.",
		Severity:    "info",
		CWE:         "CWE-1021",
	},
	{
		IsAndMatch: true,
		AndExpressions: []string{
			"setJavaScriptEnabled\\(true\\)",
			".addJavascriptInterface\\(",
		},
		Description: "Implementação de WebView insegura. Execução de código controlado pelo usuário é uma brecha de segurança.",
		Severity:    "info",
		CWE:         "CWE-749",
	},
	{
		IsAndMatch: true,
		AndExpressions: []string{
			"android\\.database\\.sqlite",
			"execSQL\\(|rawQuery\\(",
		},
		Description:   "Entrada do usuário sem validação pode causar Injeção de SQL. Toda entrada do usuário deve ser sanitizada antes de executar a operação no banco de dados.",
		Recomendation: "Sempre validar os inputs de usuário antes que o servidor execute a query e rejeitar requisições que contenham caracteres que não sejam estritamente necessários.",
		Severity:      "alta",
		CWE:           "CWE-89",
	},
	{
		IsAndMatch: true,
		AndExpressions: []string{
			"fridaserver",
			"27047|LIBFRIDA",
		},
		Description: "Este App detecta Servidores Frida.",
		Severity:    "info",
	},
	{
		IsAndMatch: true,
		AndExpressions: []string{
			"org\\.thoughtcrime\\.ssl\\.pinning",
			"PinningHelper\\.getPinnedHttpsURLConnection|PinningHelper\\.getPinnedHttpClient|PinningSSLSocketFactory\\(",
		},
		Description: "Este App uma biblioteca de SSL Pinning (org.thoughtcrime.ssl.pinning) para prevenir ataques MITM em canais seguros de comunicação.",
		Severity:    "info",
	},
	{
		ExactMatch:  "getWindow\\(.*\\)\\.\\(set|add\\)Flags\\(.*\\.FLAG_SECURE",
		Description: "Este App tem a capacidade de prevenir Screenshots de Aplicativos em Segundo Plano.",
		Severity:    "info",
	},
	{
		IsAndMatch: true,
		AndExpressions: []string{
			"import dexguard\\.util",
			"DebugDetector\\.isDebuggable",
		},
		Description: "Identificado código do DexGuard Debug Detection que detecta se o App é depurável ou não.",
		Severity:    "info",
	},
	{
		IsAndMatch: true,
		AndExpressions: []string{
			"import dexguard\\.util",
			"DebugDetector\\.isDebuggerConnected",
		},
		Description: "Identificado código do DexGuard Debugger Detection.",
		Severity:    "info",
	},
	{
		IsAndMatch: true,
		AndExpressions: []string{
			"import dexguard\\.util",
			"EmulatorDetector\\.isRunningInEmulator",
		},
		Description: "Identificado código do DexGuard Emulator Detection.",
		Severity:    "info",
	},
	{
		IsAndMatch: true,
		AndExpressions: []string{
			"import dexguard\\.util",
			"DebugDetector\\.isSignedWithDebugKey",
		},
		Description: "Identificado código do DexGuard que detecta se App está assinado com uma chave de depuração ou não.",
		Severity:    "info",
	},
	{
		IsAndMatch: true,
		AndExpressions: []string{
			"import dexguard\\.util",
			"RootDetector\\.isDeviceRooted",
		},
		Description: "Identificado código do DexGuard Root Detection.",
		Severity:    "info",
	},
	{
		IsAndMatch: true,
		AndExpressions: []string{
			"import dexguard\\.util",
			"TamperDetector\\.checkApk",
		},
		Description: "Identificado código do DexGuard App Tamper Detection.",
		Severity:    "info",
	},
	{
		IsAndMatch: true,
		AndExpressions: []string{
			"import dexguard\\.util",
			"TCertificateChecker\\.checkCertificate",
		},
		Description: "Identificado código do DexGuard Signer Certificate Tamper Detection.",
		Severity:    "info",
	},
	{
		IsAndMatch: true,
		AndExpressions: []string{
			"PackageManager\\.GET_SIGNATURES",
			"getPackageName\\(",
		},
		Description: "Este App pode estar usando um pacote assinado para detectar modificações.",
		Severity:    "info",
	},
	{
		ExactMatch:  "com\\.google\\.android\\.gms\\.safetynet\\.SafetyNetApi",
		Description: "Este App usa API SafetyNet.",
		Severity:    "info",
	},
}
