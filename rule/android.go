package rule

import (
	"regexp"

	"github.com/insidersec/insider/engine"
)

var AndroidRules []engine.Rule = []engine.Rule{
	Rule{
		ExactMatch:  regexp.MustCompile(`MODE_PRIVATE|Context\\.MODE_PRIVATE`),
		CWE:         "CWE-919",
		AverageCVSS: 5,
		Description: "App can write to App Directory. Sensitive Information should be encrypted.",
	},
	Rule{
		Or: []*regexp.Regexp{
			regexp.MustCompile(`com\.noshufou\.android\.su`),
			regexp.MustCompile(`com\.thirdparty\.superuser`),
			regexp.MustCompile(`eu\.chainfire\.supersu`),
			regexp.MustCompile(`com\.koushikdutta\.superuser`),
			regexp.MustCompile(`eu\.chainfire\.`),
		},
		CWE:         "CWE-250",
		AverageCVSS: 7.2,
		Description: "This application has packages to access root privileges (Super User). A Super User on the user's device can do absolutely anything, making the application very powerful and possibly facilitating malicious actions. etc.",
	},
	Rule{
		And: []*regexp.Regexp{
			regexp.MustCompile(`com\.fasterxml\.jackson\.databind\.ObjectMapper`),
			regexp.MustCompile(`\.enableDefaultTyping\(`),
		},
		NotAnd:      []*regexp.Regexp{regexp.MustCompile(`com\.fasterxml\.jackson\.databind\.ObjectMapper`)},
		CWE:         "CWE-502",
		AverageCVSS: 7.5,
		Description: "The app uses jackson deserialization libraryDeserialization of untrusted input can result inarbitary code execution.",
	},
	Rule{
		Or: []*regexp.Regexp{
			regexp.MustCompile(`MODE_WORLD_WRITABLE|Context\.MODE_WORLD_WRITABLE`),
			regexp.MustCompile(`openFileOutput\(\s*\".+\"\s*,\s*2\\s*\)`),
		},
		CWE:         "CWE-276",
		AverageCVSS: 6.0,
		Description: "The file is 'World Readable'. Any application can read the file.",
	},
	Rule{
		And: []*regexp.Regexp{
			regexp.MustCompile(`\.crypto\.Cipher`),
			regexp.MustCompile(`Cipher\\.getInstance\(`),
			regexp.MustCompile(`"AES"`),
		},
		NotAnd:        []*regexp.Regexp{regexp.MustCompile(`\.crypto\.Cipher`)},
		CWE:           "CWE-326",
		AverageCVSS:   5.0,
		Description:   "Use of weak encryption to store sensitive information.",
		Recomendation: "It is always recommended to use some CHF (Cryptographic Hash Function), which is mathematically strong and not reversible. SHA512 would be the most recommended hash for storing the password and it is also important to adopt some type of Salt, so that the Hash is more secure.",
	},
	Rule{
		And: []*regexp.Regexp{
			regexp.MustCompile(`\.crypto\.Cipher`),
			regexp.MustCompile(`Cipher\.getInstance\(`),
			regexp.MustCompile(`"GCM"`),
		},
		NotAnd:        []*regexp.Regexp{regexp.MustCompile(`\.crypto\.Cipher`)},
		CWE:           "CWE-326",
		AverageCVSS:   5.0,
		Description:   "The application uses GCM as the 'block mode' of the encryption algorithm. GCM is considered a weak cryptographic algorithm, as it only increases the IV value by 1, it is easy to predict the keys per block with a sufficient number of messages encrypted with the same key and / or IV.",
		Recomendation: "It is always recommended to use CBC (Cipher Block Chaining) as it offers more security that the IV will be used well and it is also important to adopt some type of 'salt', so that the hash is more secure.",
	},
	Rule{
		And: []*regexp.Regexp{
			regexp.MustCompile(`\.crypto\.Cipher`),
			regexp.MustCompile(`Cipher\.getInstance\(`),
			regexp.MustCompile(`"DES"`),
		},
		NotAnd: []*regexp.Regexp{regexp.MustCompile(`\.crypto\.Cipher`)},

		CWE:           "CWE-326",
		AverageCVSS:   5.0,
		Description:   "DES is a hash algorithm that is considered weak and can cause hash collisions.",
		Recomendation: "It is always recommended to use some CHF (Cryptographic Hash Function), which is mathematically strong and not reversible. SHA512 would be the most recommended hash for storing the password and it is also important to adopt some type of Salt, so that the Hash is more secure.",
	},
	Rule{
		And: []*regexp.Regexp{
			regexp.MustCompile(`\.crypto\.Cipher`),
			regexp.MustCompile(`Cipher\.getInstance\(\s*\"RSA/.+/NoPadding`),
		},
		NotAnd:      []*regexp.Regexp{regexp.MustCompile(`\.crypto\.Cipher`)},
		CWE:         "CWE-780",
		AverageCVSS: 5.9,
		Description: "This application uses RSA encryption without OAEP Padding. Padding prevents some types of attacks, which would use the lack of padding as an attack vector.",
	},
	Rule{
		And: []*regexp.Regexp{
			regexp.MustCompile(`\.crypto\.Cipher`),
			regexp.MustCompile(`Cipher\.getInstance\(`),
			regexp.MustCompile(`"ECB"`),
		},
		NotAnd:        []*regexp.Regexp{regexp.MustCompile(`\.crypto\.Cipher`)},
		CWE:           "CWE-327",
		AverageCVSS:   5.9,
		Description:   "The application uses ECB as the 'block mode' of the encryption algorithm. ECB is considered a weak cryptographic algorithm, as it results in the same cipher for identical blocks of plain text.",
		Recomendation: "It is always recommended to use some CHF (Cryptographic Hash Function), which is mathematically strong and not reversible. SHA512 would be the most recommended hash for storing the password and it is also important to adopt some type of Salt, so that the Hash is more secure.",
	},
	Rule{
		And: []*regexp.Regexp{
			regexp.MustCompile(`\.loadUrl\(`),
			regexp.MustCompile(`webkit\.WebView`),
		},
		NotAnd:      []*regexp.Regexp{regexp.MustCompile(`webkit\.WebView`)},
		CWE:         "CWE-919",
		AverageCVSS: 5.0,
		Description: "The WebView loads files from external storage. External storage files can be modified by any application.",
	},
	Rule{
		ExactMatch:  regexp.MustCompile(`setVisibility\(View\.GONE\)|setVisibility\(View\.INVISIBLE\)`),
		CWE:         "CWE-919",
		AverageCVSS: 4.3,
		Description: "Invisible elements in the view can be used to hide data from the user, but can still be leaked.",
	},
	Rule{
		And:           []*regexp.Regexp{regexp.MustCompile(`android\.database\.sqlite`), regexp.MustCompile(`execSQL\(|rawQuery\(`)},
		NotAnd:        []*regexp.Regexp{regexp.MustCompile(`android\.database\.sqlite`)},
		CWE:           "CWE-89",
		AverageCVSS:   5.9,
		Description:   "User input without validation can cause SQL Injection. All user input must be sanitized before performing the operation on the database.",
		Recomendation: "Always validate user inputs before the server executes the query and reject requests that contain characters that are not strictly necessary.",
	},
	Rule{
		And: []*regexp.Regexp{
			regexp.MustCompile(`\.net\.ssl`),
			regexp.MustCompile(`TrustAllSSLSocket-Factory|AllTrustSSLSocketFactory|NonValidatingSSLSocketFactory|net\.SSLCertificateSocketFactory|ALLOW_ALL_HOSTNAME_VERIFIER|\.setDefaultHostnameVerifier\(|NullHostnameVerifier\(`),
		},
		NotAnd:      []*regexp.Regexp{regexp.MustCompile(`\.net\.ssl`)},
		CWE:         "CWE-295",
		AverageCVSS: 7.4,
		Description: "Insecure implementation of SSL. Trusting any certificate or accepting self-signed certificates can cause a serious security breach, making the application vulnerable to MITM (Man In The Middle) attacks.",
	},
	Rule{
		ExactMatch:    regexp.MustCompile(`openFileOutput\(\s*".+"\s*,\s*3\s*\)`),
		CWE:           "CWE-276",
		AverageCVSS:   6.0,
		Description:   "The file is 'World Readable' and 'World Writable'. Any application can read the file.",
		Recomendation: "According to official Google documentation, both MODE_WORLD_WRITABLE and MODE_WORLD_READABLE modes are depreciated. It is recommended to use MODE_PRIVATE.",
	},
	Rule{
		ExactMatch:    regexp.MustCompile(`getInstance("md4")|getInstance("rc2")|getInstance("rc4")|getInstance("RC4")|getInstance("RC2")|getInstance("MD4")`),
		CWE:           "CWE-327",
		AverageCVSS:   7.4,
		Description:   "A hash algorithm used is considered weak and can cause hash collisions.",
		Recomendation: "It is always recommended to use some CHF (Cryptographic Hash Function), which is mathematically strong and not reversible. SHA512 would be the most recommended hash for storing the password and it is also important to adopt some type of Salt, so that the Hash is more secure.",
	},
	Rule{
		ExactMatch:    regexp.MustCompile(`MessageDigest\.getInstance\("*MD5"*\)|MessageDigest\.getInstance\("*md5"*\)|DigestUtils\.md5\(`),
		CWE:           "CWE-327",
		AverageCVSS:   7.4,
		Description:   "MD5 is a hash algorithm that is considered weak and can cause hash collisions.",
		Recomendation: "It is always recommended to use some CHF (Cryptographic Hash Function), which is mathematically strong and not reversible. SHA512 would be the most recommended hash for storing the password and it is also important to adopt some type of Salt, so that the Hash is more secure.",
	},
	Rule{
		ExactMatch:    regexp.MustCompile(`MessageDigest\.getInstance\("*SHA-1"*\)|MessageDigest\.getInstance\("*sha-1"*\)|DigestUtils\.sha\(`),
		CWE:           "CWE-327",
		AverageCVSS:   7.4,
		Description:   "SHA-1 is a hash algorithm that is considered weak and can cause hash collisions.",
		Recomendation: "It is always recommended to use some CHF (Cryptographic Hash Function), which is mathematically strong and not reversible. SHA512 would be the most recommended hash for storing the password and it is also important to adopt some type of Salt, so that the Hash is more secure.",
	},
	Rule{
		And:           []*regexp.Regexp{regexp.MustCompile(`java\.util\.Random`), regexp.MustCompile(`Random\(\)`)},
		CWE:           "CWE-330",
		AverageCVSS:   7.5,
		Description:   "The application uses a predictable, therefore insecure, random number generator.",
		Recomendation: "For a better implementation it would be to use the package java.util.SecureRandom.",
	},
	Rule{
		Or:          []*regexp.Regexp{regexp.MustCompile("0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00"), regexp.MustCompile("0x01,0x02,0x03,0x04,0x05,0x06,0x07")},
		CWE:         "CWE-329",
		AverageCVSS: 9.8,
		Description: "The Application uses weak Initialization Vectors (weak IVs in encryption), such as '0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ' or '0x01,0x02,0x03,0x04,0x05,0x06 , 0x07 '. Failure to use random IVs makes the application vulnerable to dictionary attacks.",
	},
}
