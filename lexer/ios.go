package lexer

import (
	"github.com/insidersec/insider/util"
	"log"
)

func IosRules(lang string) []Rule {
	var all []Rule

	var obj Rule
	obj.ExactMatch = "\\w+.withUnsafeBytes\\s*{.*"
	obj.CWE = "CWE-789"
	obj.AverageCVSS = 0
	obj.Severity = util.GetSeverity(lang, 0)
	obj.Description_pt_br = "O uso desta implementação de '.withUnsafeBytes' pode levar à decisão do compilador de usar APIs não seguras, como _malloc e _strcpy, pois o método chama o fechamento com um UnsafeRawBufferPointer."
	obj.Description_en = "Using this implementation of '.withUnsafeBytes' can lead to the compiler's decision to use unsafe APIs, such as _malloc and _strcpy, as the method calls closing with an UnsafeRawBufferPointer."
	obj.Description_es = "El uso de esta implementación de '.withUnsafeBytes' puede llevar a la decisión del compilador de usar API inseguras, como _malloc y _strcpy, ya que el método llama al cierre con un UnsafeRawBufferPointer."
	obj.Recomendation_pt_br = "Sempre que possível evite o uso de buffers ou ponteiros de memória que não tem seu tamanho válidado."
	obj.Recomendation_en = "Whenever possible, avoid using buffers or memory pointers that do not have a valid size."
	obj.Recomendation_es = "Siempre que sea posible, evite usar memorias intermedias o punteros de memoria que no tengan un tamaño válido."
	all = append(all, obj)

	obj = Rule{}
	obj.ExactMatch = "Keychain|kSecAttrAccessibleWhenUnlocked|kSecAttrAccessibleAfterFirstUnlock|SecItemAdd|SecItemUpdate|NSDataWritingFileProtectionComplete"
	obj.AverageCVSS = 0
	obj.Severity = util.GetSeverity(lang, 0)
	obj.Description_pt_br = "Operações de E / S de arquivo local."
	obj.Description_en = "Local File I/O Operations."
	obj.Description_es = "Operaciones de E / S de archivos locales."
	all = append(all, obj)

	obj = Rule{}
	obj.ExactMatch = "UIWebView"
	obj.AverageCVSS = 0
	obj.Severity = util.GetSeverity(lang, 0)
	obj.Description_pt_br = "Componente WebView."
	obj.Description_en = "WebView Component."
	obj.Description_es = "Componente WebView."
	all = append(all, obj)

	obj = Rule{}
	obj.ExactMatch = "RNEncryptor|RNDecryptor|AESCrypt"
	obj.AverageCVSS = 0
	obj.Severity = util.GetSeverity(lang, 0)
	obj.Description_pt_br = "API de criptografia."
	obj.Description_en = "Encryption API."
	obj.Description_es = "API de cifrado."
	all = append(all, obj)

	obj = Rule{}
	obj.ExactMatch = "PDKeychainBindings"
	obj.AverageCVSS = 0
	obj.Severity = util.GetSeverity(lang, 0)
	obj.Description_pt_br = "Acesso ao Keychain."
	obj.Description_en = "Keychain Access."
	obj.Description_es = "Accesso al Keychain."
	all = append(all, obj)

	obj = Rule{}
	obj.AndExpressions = []string{"loadRequest",
		"webView"}
	obj.IsAndMatch = true
	obj.AverageCVSS = 0
	obj.Severity = util.GetSeverity(lang, 0)
	obj.Description_pt_br = "Solicitação de carga do WebView."
	obj.Description_en = "WebView Load Request."
	obj.Description_es = "Solicitud de carga de WebView."
	all = append(all, obj)

	obj = Rule{}
	obj.AndExpressions = []string{"NSHTTPCookieStorage",
		"sharedHTTPCookieStorage"}
	obj.IsAndMatch = true
	obj.AverageCVSS = 0
	obj.Severity = util.GetSeverity(lang, 0)
	obj.Description_pt_br = "Armazenamento de Cookie."
	obj.Description_en = "Cookie Storage."
	obj.Description_es = "Almacenamiento de Cookie."
	all = append(all, obj)

	obj = Rule{}
	obj.AndExpressions = []string{"UIPasteboard",
		"generalPasteboard"}
	obj.IsAndMatch = true
	obj.AverageCVSS = 0
	obj.Severity = util.GetSeverity(lang, 0)
	obj.Description_pt_br = "Definir ou ler a área de transferência"
	obj.Description_en = "Set or Read Clipboard"
	obj.Description_es = "Establecer o leer el Clipboard"
	all = append(all, obj)

	obj = Rule{}
	obj.ExactMatch = "(strcpy)|(memcpy)|(strcat)|(strncat)|(strncpy)|(sprintf)|(vsprintf)"
	obj.CWE = "CWE-676"
	obj.AverageCVSS = 2.2
	obj.Severity = util.GetSeverity(lang, 3)
	obj.Description_pt_br = "O aplicativo pode conter APIs proibidas. Essas APIs são inseguras e não devem ser usadas."
	obj.Description_en = "The application may contain prohibited APIs. These APIs are insecure and should not be used."
	obj.Description_es = "La aplicación puede contener API prohibidas. Estas API son inseguras y no deben usarse."
	obj.Recomendation_pt_br = " Evite o uso de API(s) inseguras e nunca confie em dados inseridos pelo usuário, sempre sanitizar os dados inseridos."
	obj.Recomendation_en = "Avoid using unsafe API (s) and never rely on data entered by the user, always sanitize the data entered."
	obj.Recomendation_es = "Evite el uso de API no seguras y nunca confíe en los datos ingresados por el usuario, siempre desinfecte los datos ingresados."
	all = append(all, obj)

	obj = Rule{}
	obj.ExactMatch = "canAuthenticateAgainstProtectionSpace|continueWithoutCredentialForAuthenticationChallenge|kCFStreamSSLAllowsExpiredCertificates|kCFStreamSSLAllowsAnyRoot|kCFStreamSSLAllowsExpiredRoots|validatesSecureCertificate\\s*=\\s*(no|NO)|allowInvalidCertificates\\s*=\\s*(YES|yes)"
	obj.CWE = "CWE-295"
	obj.AverageCVSS = 7.4
	obj.Severity = util.GetSeverity(lang, 3)
	obj.Description_pt_br = "O aplicativo permite certificados SSL autoassinados ou inválidos. O aplicativo é vulnerável a ataques de MITM (Man-In-The-Middle)."
	obj.Description_en = "The application allows self-signed or invalid SSL certificates. The application is vulnerable to MITM (Man-In-The-Middle) attacks."
	obj.Description_es = "La aplicación permite certificados SSL autofirmados o no válidos. La aplicación es vulnerable a los ataques MITM (Man-In-The-Middle)."
	obj.Recomendation_pt_br = "Os certificados devem ser cuidadosamente gerenciados e verificados para garantir que os dados sejam criptografados com a chave pública do proprietário pretendido."
	obj.Recomendation_en = "Certificates must be carefully managed and verified to ensure that data is encrypted with the intended owner's public key."
	obj.Recomendation_es = "Los certificados deben administrarse y verificarse cuidadosamente para garantizar que los datos se cifren con la clave pública del propietario previsto."
	all = append(all, obj)

	obj = Rule{}
	obj.ExactMatch = "setAllowsAnyHTTPSCertificate:\\s*YES|allowsAnyHTTPSCertificateForHost|loadingUnvalidatedHTTPSPage\\s*=\\s*(YES|yes)"
	obj.CWE = "CWE-295"
	obj.AverageCVSS = 7.4
	obj.Severity = util.GetSeverity(lang, 3)
	obj.Description_pt_br = "O UIWebView no aplicativo ignora erros de SSL e aceita qualquer certificado SSL. O aplicativo é vulnerável a ataques do MITM (Man-In-The-Middle)."
	obj.Description_en = "The in-app UIWebView ignores SSL errors and accepts any SSL certificate. The application is vulnerable to attacks from MITM (Man-In-The-Middle)."
	obj.Description_es = "La aplicación UIWebView ignora los errores de SSL y acepta cualquier certificado SSL. La aplicación es vulnerable a los ataques de MITM (Man-In-The-Middle)."
	obj.Recomendation_pt_br = "Os certificados devem ser cuidadosamente gerenciados e verificados para garantir que os dados sejam criptografados com a chave pública do proprietário pretendido."
	obj.Recomendation_en = "Certificates must be carefully managed and verified to ensure that data is encrypted with the intended owner's public key."
	obj.Recomendation_es = "Los certificados deben administrarse y verificarse cuidadosamente para garantizar que los datos se cifren con la clave pública del propietario previsto."
	all = append(all, obj)

	obj = Rule{}
	obj.ExactMatch = "NSLog|NSAssert|fprintf|fprintf|Logging"
	obj.CWE = "CWE-532"
	obj.AverageCVSS = 0
	obj.Severity = util.GetSeverity(lang, 0)
	obj.Description_pt_br = "O binário pode usar a função NSLog para registro em log. As informações confidenciais nunca devem ser registradas."
	obj.Description_en = "The binary can use the NSLog function for logging. Confidential information should never be recorded."
	obj.Description_es = "El binario puede usar la función NSLog para iniciar sesión. La información confidencial nunca debe ser registrada."
	obj.Recomendation_pt_br = "Evitar que dados sensíveis sejam logados em produção."
	obj.Recomendation_en = "Prevent sensitive data from being logged into production."
	obj.Recomendation_es = "Evite que los datos confidenciales se registren en producción."
	all = append(all, obj)

	obj = Rule{}
	obj.ExactMatch = "UIPasteboardChangedNotification|generalPasteboard\\]\\.string"
	obj.AverageCVSS = 0
	obj.Severity = util.GetSeverity(lang, 0)
	obj.Description_pt_br = "O aplicativo permite listar as alterações no Clipboard. Alguns malwares também listam alterações no Clipboard."
	obj.Description_en = "The application allows you to list the changes on the Clipboard. Some malware also lists changes to the Clipboard."
	obj.Description_es = "La aplicación le permite enumerar los cambios en el Clipboard. Algunos programas maliciosos también incluyen cambios en el Clipboard."
	all = append(all, obj)

	obj = Rule{}
	obj.ExactMatch = "sqlite3_exec"
	obj.AverageCVSS = 0
	obj.Severity = util.GetSeverity(lang, 0)
	obj.Description_pt_br = "O aplicativo está usando SQLite. Informações confidencias desem ser criptografadas."
	obj.Description_en = "The application is using SQLite. Confidential information must be encrypted"
	obj.Description_es = "La aplicación está usando SQLite. La información confidencial debe estar encriptada"
	all = append(all, obj)

	obj = Rule{}
	obj.ExactMatch = "NSTemporaryDirectory\\(\\),"
	obj.CWE = "CWE-22"
	obj.AverageCVSS = 7.5
	obj.Severity = util.GetSeverity(lang, 0)
	obj.Description_pt_br = "Utilização do usuário em \"NSTemporaryDirectory()\" não é confiável, pode resultar em vulnerabilidades no diretório."
	obj.Description_en = "User use in \"NSTemporaryDirectory ()\" is unreliable, it can result in vulnerabilities in the directory."
	obj.Description_es = "El uso del usuario en \"NSTemporaryDirectory ()\" no es confiable, puede generar vulnerabilidades en el directorio."
	all = append(all, obj)

	obj = Rule{}
	obj.AndExpressions = []string{"loadHTMLString",
		"webView"}
	obj.IsAndMatch = true
	obj.CWE = "CWE-95"
	obj.AverageCVSS = 8.8
	obj.Severity = util.GetSeverity(lang, 0)
	obj.Description_pt_br = "A entrada do usuário não sanitizada em 'loadHTMLString' pode resultar em uma injeção de JavaScript no contexto do seu aplicativo, permitindo acesso a dados privados."
	obj.Description_en = "User input not sanitized in 'loadHTMLString' can result in an injection of JavaScript in the context of your application, allowing access to private data."
	obj.Description_es = "La entrada del usuario no desinfectada en 'loadHTMLString' puede provocar una inyección de JavaScript en el contexto de su aplicación, lo que permite el acceso a datos privados."
	all = append(all, obj)

	obj = Rule{}
	obj.AndExpressions = []string{"SFAntiPiracy.h",
		"SFAntiPiracy",
		"isJailbroken"}
	obj.IsAndMatch = true
	obj.AverageCVSS = 0
	obj.Severity = util.GetSeverity(lang, 0)
	obj.Description_pt_br = "SFAntiPiracy Jailbreak checks found"
	obj.Description_en = "Verificações SFAntiPiracy Jailbreak encontradas"
	obj.Description_es = "SFAntiPiracy Jailbreak comprobaciones encontradas"
	all = append(all, obj)

	obj = Rule{}
	obj.AndExpressions = []string{"SFAntiPiracy.h",
		"SFAntiPiracy",
		"isPirated"}
	obj.IsAndMatch = true
	obj.AverageCVSS = 0
	obj.Severity = util.GetSeverity(lang, 0)
	obj.Description_pt_br = "SFAntiPiracy Jailbreak checks found"
	obj.Description_en = "Verificações SFAntiPiracy Jailbreak encontradas"
	obj.Description_es = "SFAntiPiracy Jailbreak comprobaciones encontradas"
	all = append(all, obj)

	obj = Rule{}
	obj.AndExpressions = []string{"CommonDigest.h",
		"CC_MD5"}
	obj.IsAndMatch = true
	obj.CWE = "CWE-327"
	obj.AverageCVSS = 7.4
	obj.Severity = util.GetSeverity(lang, 3)
	obj.Description_pt_br = "MD5 é um hash fraco, podendo gerar hashs repitidos."
	obj.Description_en = "MD5 is a weak hash, which can generate repeated hashes."
	obj.Description_es = "MD5 es un hash débil, que puede generar hashes repetidos."
	obj.Recomendation_pt_br = "Quando for necessário armazenar ou transmitir dados sensíveis, dê preferência a algoritmos de criptografia modernos e verifique com frequência se o algoritmo utilizado não se tornou obsoleto."
	obj.Recomendation_en = "When it is necessary to store or transmit sensitive data, give preference to modern encryption algorithms and check frequently that the algorithm used has not become obsolete."
	obj.Recomendation_es = "Cuando sea necesario almacenar o transmitir datos confidenciales, dé preferencia a los algoritmos de cifrado modernos y verifique con frecuencia que el algoritmo utilizado no haya quedado obsoleto."
	all = append(all, obj)

	obj = Rule{}
	obj.AndExpressions = []string{"CommonDigest.h",
		"CC_SHA1"}
	obj.IsAndMatch = true
	obj.CWE = "CWE-327"
	obj.AverageCVSS = 5.9
	obj.Severity = util.GetSeverity(lang, 3)
	obj.Description_pt_br = "SHA1 é um hash fraco, podendo gerar hashs repitidos."
	obj.Description_en = "SHA1 is a weak hash, which can generate repeated hashes."
	obj.Description_es = "SHA1 es un hash débil, que puede generar hashes repetidos."
	obj.Recomendation_pt_br = "Quando for necessário armazenar ou transmitir dados sensíveis, dê preferência a algoritmos de criptografia modernos e verifique com frequência se o algoritmo utilizado não se tornou obsoleto."
	obj.Recomendation_en = "When it is necessary to store or transmit sensitive data, give preference to modern encryption algorithms and check frequently that the algorithm used has not become obsolete."
	obj.Recomendation_es = "Cuando sea necesario almacenar o transmitir datos confidenciales, dé preferencia a los algoritmos de cifrado modernos y verifique con frecuencia que el algoritmo utilizado no haya quedado obsoleto."
	all = append(all, obj)

	obj = Rule{}
	obj.AndExpressions = []string{"kCCOptionECBMode",
		"kCCAlgorithmAES"}
	obj.IsAndMatch = true
	obj.CWE = "CWE-327"
	obj.AverageCVSS = 5.9
	obj.Severity = util.GetSeverity(lang, 3)
	obj.Description_pt_br = "O aplicativo usa o modo ECB no algoritmo de criptografia. Sabe-se que o modo ECB é fraco, pois resulta no mesmo texto cifrado para blocos idênticos de texto sem formatação."
	obj.Description_en = "The application uses ECB mode in the encryption algorithm. It is known that the ECB mode is weak, as it results in the same ciphertext for identical blocks of plain text."
	obj.Description_es = "La aplicación utiliza el modo ECB en el algoritmo de cifrado. Se sabe que el modo ECB es débil, ya que da como resultado el mismo texto cifrado para bloques idénticos de texto sin formato."
	obj.Recomendation_pt_br = "Quando for necessário armazenar ou transmitir dados sensíveis, dê preferência a algoritmos de criptografia modernos e verifique com frequência se o algoritmo utilizado não se tornou obsoleto."
	obj.Recomendation_en = "When it is necessary to store or transmit sensitive data, give preference to modern encryption algorithms and check frequently that the algorithm used has not become obsolete."
	obj.Recomendation_es = "Cuando sea necesario almacenar o transmitir datos confidenciales, dé preferencia a los algoritmos de cifrado modernos y verifique con frecuencia que el algoritmo utilizado no haya quedado obsoleto."
	all = append(all, obj)

	obj = Rule{}
	obj.AndExpressions = []string{"ptrace_ptr",
		"PT_DENY_ATTACH"}
	obj.IsAndMatch = true
	obj.AverageCVSS = 0
	obj.Severity = util.GetSeverity(lang, 0)
	obj.Description_pt_br = "O aplicativo possui anti-debugger usando ptrace()"
	obj.Description_en = "The application has anti-debugger using ptrace ()"
	obj.Description_es = "La aplicación tiene anti-depurador usando ptrace ()"
	all = append(all, obj)

	obj = Rule{}
	obj.AndExpressions = []string{"mach/mach_init.h",
		"MACH_PORT_VALID|mach_task_self\\(\\)"}
	obj.IsAndMatch = true
	obj.AverageCVSS = 0
	obj.Severity = util.GetSeverity(lang, 0)
	obj.Description_pt_br = "O aplicativo possui anti-debugger usando Mach Exception Ports."
	obj.Description_en = "The application has anti-debugger using Mach Exception Ports."
	obj.Description_es = "La aplicación tiene anti-depurador utilizando puertos de excepción Mach."
	all = append(all, obj)

	obj = Rule{}
	obj.ExactMatch = "(\\w+\\s*=\\s*UIPasteboard)"
	obj.AverageCVSS = 0
	obj.Severity = util.GetSeverity(lang, 0)
	obj.Description_pt_br = "O aplicativo copia dados para o Clipboard. Dados confidenciais não devem ser copiados para o Clipboard, pois outros aplicativos podem acessar."
	obj.Description_en = "The application copies data to the Clipboard. Confidential data must not be copied to the Clipboard, as other applications can access it."
	obj.Description_es = "La aplicación copia datos al Clipboard. Los datos confidenciales no deben copiarse en el Clipboard, ya que otras aplicaciones pueden acceder a él."
	all = append(all, obj)

	obj = Rule{}
	obj.OrExpressions = []string{"/Applications/Cydia.app",
		"/Library/MobileSubstrate/MobileSubstrate.dylib",
		"/usr/sbin/sshd",
		"/etc/apt",
		"cydia://",
		"/var/lib/cydia",
		"/Applications/FakeCarrier.app",
		"/Applications/Icy.app",
		"/Applications/IntelliScreen.app",
		"/Applications/SBSettings.app",
		"/Library/MobileSubstrate/DynamicLibraries/LiveClock.plist",
		"/System/Library/LaunchDaemons/com.ikey.bbot.plist",
		"/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist",
		"/etc/ssh/sshd_config",
		"/private/var/tmp/cydia.log",
		"/usr/libexec/ssh-keysign",
		"/Applications/MxTube.app",
		"/Applications/RockApp.app",
		"/Applications/WinterBoard.app",
		"/Applications/blackra1n.app",
		"/Library/MobileSubstrate/DynamicLibraries/Veency.plist",
		"/private/var/lib/apt",
		"/private/var/lib/cydia",
		"/private/var/mobile/Library/SBSettings/Themes",
		"/private/var/stash",
		"/usr/bin/sshd",
		"/usr/libexec/sftp-server",
		"/var/cache/apt",
		"/var/lib/apt",
		"/usr/sbin/frida-server",
		"/usr/bin/cycript",
		"/usr/local/bin/cycript",
		"/usr/lib/libcycript.dylib",
		"frida-server"}
	obj.IsOrMatch = true
	obj.AverageCVSS = 0
	obj.Severity = util.GetSeverity(lang, 0)
	obj.Description_pt_br = "O aplicativo pode conter mecanismos de detecção de Jailbreak."
	obj.Description_en = "The application may contain Jailbreak detection mechanisms."
	obj.Description_es = "La aplicación puede contener mecanismos de detección de Jailbreak."

	all = append(all, obj)

	log.Println("Rules", len(all))

	return all

}
