package lexer

func JavascriptRules(lang string) []Rule {

	var all []Rule
	var obj Rule
	obj.ExactMatch = "(eval\\(.+)(?:req\\.|req\\.query|req\\.body|req\\.param)"
	obj.CWE = "CWE-94"
	obj.AverageCVSS = 7
	obj.Description_en = "The eval function is extremely dangerous. Because if any user input is not handled correctly and passed to it, it will be possible to execute code remotely in the context of your application (RCE - Remote Code Executuion)."
	all = append(all, obj)

	obj = Rule{}
	obj.ExactMatch = "(?:\\[|)(?:'|\")NODE_TLS_REJECT_UNAUTHORIZED(?:'|\")(?:\\]|)\\s*=\\s*(?:'|\")*0(?:'|\")"
	obj.CWE = "CWE-295"
	obj.AverageCVSS = 7.1
	obj.Description_en = "If the NODE_TLS_REJECT_UNAUTHORIZED option is disabled, the Node.js server will accept certificates that are self-signed, allowing an attacker to bypass the TLS security layer."
	all = append(all, obj)

	obj = Rule{}
	obj.ExactMatch = "createHash\\((?:'|\")md5(?:'|\")"
	obj.CWE = "CWE-327"
	obj.AverageCVSS = 7.1
	obj.Description_en = "The MD5 hash algorithm that was used is considered weak. It can also cause hash collisions."
	obj.Recomendation_en = "It is always recommended to use some CHF (Cryptographic Hash Function), which is mathematically strong and not reversible. SHA512 would be the most recommended hash for storing the password and it is also important to adopt some type of Salt, so that the Hash is more secure."
	all = append(all, obj)

	obj = Rule{}
	obj.ExactMatch = "createHash\\((?:'|\")sha1(?:'|\")"
	obj.CWE = "CWE-327"
	obj.AverageCVSS = 7.1
	obj.Description_en = "The SHA1 hash algorithm that was used is considered weak. It can also cause hash collisions."
	obj.Recomendation_en = "It is always recommended to use some CHF (Cryptographic Hash Function), which is mathematically strong and not reversible. SHA512 would be the most recommended hash for storing the password and it is also important to adopt some type of Salt, so that the Hash is more secure."
	all = append(all, obj)

	obj = Rule{}
	obj.ExactMatch = "\\.createReadStream\\(.*(?:req\\.|req\\.query|req\\.body|req\\.param)"
	obj.CWE = "CWE-35"
	obj.AverageCVSS = 5.5
	obj.Description_en = "User data passed untreated to the 'createReadStream' function can cause a Directory Traversal attack. This attack exploits the lack of security, with the attacker gaining unauthorized access to the file system."
	all = append(all, obj)

	obj = Rule{}
	obj.ExactMatch = "\\.readFile\\(.*(?:req\\.|req\\.query|req\\.body|req\\.param)"
	obj.CWE = "CWE-35"
	obj.AverageCVSS = 5.5
	obj.Description_en = "User data passed untreated to the 'createReadStream' function can cause a Directory Traversal attack. This attack exploits the lack of security, with the attacker gaining unauthorized access to the file system."
	all = append(all, obj)

	obj = Rule{}
	obj.ExactMatch = "\\.(find|drop|create|explain|delete|count|bulk|copy).*\\n*{.*\\n*\\$where(?:'|\"|):.*(?:req\\.|req\\.query|req\\.body|req\\.param)"
	obj.CWE = "CWE-89"
	obj.AverageCVSS = 6.3
	obj.Description_en = "Passing untreated parameters to queries in the database can cause an injection of SQL / NoSQL. The attacker is able to insert a custom and improper SQL statement through the data entry of an application."
	all = append(all, obj)

	obj = Rule{}
	obj.AndExpressions = []string{"require\\((?:'|\")request(?:'|\")\\)",
		"request\\(.*(req\\.|req\\.query|req\\.body|req\\.param)"}
	obj.IsAndMatch = true
	obj.CWE = "CWE-918"
	obj.AverageCVSS = 6.5
	obj.Description_en = "Allows user input data to be used as parameters for the 'request' method. Without proper handling, it could cause a Server Side Request Forgery vulnerability. Which is a type of exploitation in which an attacker abuses the functionality of a server, causing it to access or manipulate information in that server's domain."
	all = append(all, obj)

	obj = Rule{}
	obj.AndExpressions = []string{"require\\((?:'|\")request(?:'|\")\\)",
		"\\.get\\(.*(req\\.|req\\.query|req\\.body|req\\.param)"}
	obj.IsAndMatch = true
	obj.CWE = "CWE-918"
	obj.AverageCVSS = 6.5
	obj.Description_en = "Allows user input data to be used as parameters for the 'request.get' method. Without proper handling, it could cause a Server Side Request Forgery vulnerability. Which is a type of exploitation in which an attacker abuses the functionality of a server, causing it to access or manipulate information in that server's domain."
	all = append(all, obj)

	return all

}
