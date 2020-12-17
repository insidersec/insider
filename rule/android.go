package rule

import (
	"regexp"

	"github.com/insidersec/insider/engine"
)

var AndroidRules []engine.Rule = []engine.Rule{

	Rule{
		And: []*regexp.Regexp{regexp.MustCompile(`\.crypto\.Cipher`), regexp.MustCompile(`Cipher\.getInstance\(\s*"RSA/.+/NoPadding`)}, NotAnd: []*regexp.Regexp{regexp.MustCompile(`\.crypto\.Cipher`)},
		CWE:           "CWE-780",
		AverageCVSS:   5.9,
		Description:   "This application uses RSA encryption without OAEP (Optimal Asymmetric Encryption Padding), OAEP has been standardized as PKCS # 1 v2 and RFC 2437. The padding scheme makes the operation 'semantically secure' and prevents some types of attacks, which would use the lack of padding as an attack vector.",
		Recomendation: "It is recommended to use RSA in conjunction with OAEP, the RSA-OAEP method makes padding attacks much more complex and often unviable.",
	},

	Rule{
		And: []*regexp.Regexp{regexp.MustCompile(`\.crypto\.Cipher`), regexp.MustCompile(`Cipher\.getInstance\(`), regexp.MustCompile(`"DES"`)}, NotAnd: []*regexp.Regexp{regexp.MustCompile(`\.crypto\.Cipher`)},
		CWE:           "CWE-327",
		AverageCVSS:   5.9,
		Description:   "DES (Data Encryption Standard) is a symmetric key cryptographic algorithm. Its 56-bit key makes it insecure for modern applications, it was developed in 1970, approved as a standard in 1976 and in 1977 the first vulnerability was discovered. Today it can be broken in about 2 days with a modern graphics card.",
		Recomendation: "Whenever possible, the use of DES encryption should be avoided, the recommended encryption is AES (Advanced Encryption Standard) with 256 bits, which has been approved by the American security agency (NSA) for encrypting top secret information.",
	},

	Rule{
		Or:            []*regexp.Regexp{regexp.MustCompile(`MODE_WORLD_WRITABLE|Context\.MODE_WORLD_WRITABLE`), regexp.MustCompile(`openFileOutput\(\s*".+"\s*,\s*2\s*\)`)},
		CWE:           "CWE-276",
		AverageCVSS:   6,
		Description:   "The file is 'World Readable'. Any application can read the file.",
		Recomendation: "According to official Google documentation, MODE_WORLD_WRITABLE mode is deprecated. It is recommended to use MODE_PRIVATE.",
	},

	Rule{
		ExactMatch:    regexp.MustCompile(`openFileOutput\(\s*".+"\s*,\s*3\s*\)`),
		CWE:           "CWE-276",
		AverageCVSS:   6,
		Description:   "The file is 'World Readable' and 'World Writable'. Any application can read the file.",
		Recomendation: "According to official Google documentation, both MODE_WORLD_WRITABLE and MODE_WORLD_READABLE modes are depreciated. It is recommended to use MODE_PRIVATE.",
	},

	Rule{
		ExactMatch:    regexp.MustCompile(`MessageDigest\.getInstance\("*MD5"*\)|MessageDigest\.getInstance\("*md5"*\)|DigestUtils\.md5\(`),
		CWE:           "CWE-327",
		AverageCVSS:   7.4,
		Description:   "MD5 is a hash algorithm considered weak and can return the same result for two different contents, which can cause collisions and in extreme cases it can cause a security breach. https://en.wikipedia.org/wiki/Collision_resistance",
		Recomendation: "It is recommended to use some CHF (Cryptographic Hash Function), which is mathematically strong and not reversible. SHA512 would be the most recommended hash for storing the password and it is also important to adopt some type of Salt, so that the Hash is more secure.",
	},

	Rule{
		ExactMatch:    regexp.MustCompile(`getInstance("md4")|getInstance("rc2")|getInstance("rc4")|getInstance("RC4")|getInstance("RC2")|getInstance("MD4")`),
		CWE:           "CWE-327",
		AverageCVSS:   7.4,
		Description:   "MD4 is a hash algorithm considered weak and can return the same result for two different contents, which can cause collisions and in extreme cases it can cause a security breach. https://en.wikipedia.org/wiki/Collision_resistance",
		Recomendation: "It is recommended to use some CHF (Cryptographic Hash Function), which is mathematically strong and not reversible. SHA512 would be the most recommended hash for storing the password and it is also important to adopt some type of Salt, so that the Hash is more secure.",
	},

	Rule{
		Or:            []*regexp.Regexp{regexp.MustCompile(`.getExternalStorage`), regexp.MustCompile(`.getExternalFilesDir\(`)},
		CWE:           "CWE-276",
		AverageCVSS:   5.5,
		Description:   "The application can read / write to external storage. External storage files can be modified by any application.",
		Recomendation: "",
	},

	Rule{
		ExactMatch:    regexp.MustCompile(`\.createTempFile\(`),
		CWE:           "CWE-276",
		AverageCVSS:   5.5,
		Description:   "The application creates a temporary file. Sensitive information should not be stored in temporary files.",
		Recomendation: "",
	},

	Rule{
		Or:            []*regexp.Regexp{regexp.MustCompile(`0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00`), regexp.MustCompile(`0x01,0x02,0x03,0x04,0x05,0x06,0x07`)},
		CWE:           "CWE-329",
		AverageCVSS:   9.8,
		Description:   "The Application uses weak Initialization Vectors (weak IVs in encryption), such as '0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ' or '0x01,0x02,0x03,0x04,0x05,0x06 , 0x07 '. Failure to use random IVs makes the application vulnerable to dictionary attacks.",
		Recomendation: "",
	},

	Rule{
		And: []*regexp.Regexp{regexp.MustCompile(`onReceivedSslError\(WebView`), regexp.MustCompile(`\.proceed\(\);`), regexp.MustCompile(`webkit\.WebView`)}, NotAnd: []*regexp.Regexp{regexp.MustCompile(`webkit\.WebView`)},
		CWE:           "CWE-295",
		AverageCVSS:   7.4,
		Description:   "Insecure WebView implementation. WebView ignores SSL Certificate errors and accepts SSL. This application is vulnerable to MITM attacks.",
		Recomendation: "",
	},

	Rule{
		And: []*regexp.Regexp{regexp.MustCompile(`android\.database\.sqlite`), regexp.MustCompile(`execSQL\(|rawQuery\(`)}, NotAnd: []*regexp.Regexp{regexp.MustCompile(`android\.database\.sqlite`)},
		CWE:           "CWE-89",
		AverageCVSS:   5.9,
		Description:   "User input without validation can cause SQL Injection. All user input must be sanitized before performing the operation on the database.",
		Recomendation: "Always validate user inputs before the server executes the query and reject requests that contain characters that are not strictly necessary.",
	},

	Rule{
		ExactMatch:    regexp.MustCompile(`SQLiteOpenHelper\.getWritableDatabase\(`),
		CWE:           "CWE-312",
		AverageCVSS:   1,
		Description:   "The application uses SQL Cipher, but the key may be contained in the source code (hardcoded).",
		Recomendation: "",
	},

	Rule{
		And: []*regexp.Regexp{regexp.MustCompile(`android\.app\.DownloadManager`), regexp.MustCompile(`getSystemService\(DOWNLOAD_SERVICE\)`)}, NotAnd: []*regexp.Regexp{regexp.MustCompile(`android\.app\.DownloadManager`)},
		CWE:           "CWE-494",
		AverageCVSS:   7.5,
		Description:   "The application downloads files using the Android Download Manager.",
		Recomendation: "",
	},

	Rule{
		And: []*regexp.Regexp{regexp.MustCompile(`\.setWebContentsDebuggingEnabled\(true\)`), regexp.MustCompile(`webkit\.WebView`)}, NotAnd: []*regexp.Regexp{regexp.MustCompile(`webkit\.WebView`)},
		CWE:           "CWE-215",
		AverageCVSS:   5.4,
		Description:   "Remote WebView debugging is enabled.",
		Recomendation: "",
	},

	Rule{
		And: []*regexp.Regexp{regexp.MustCompile(`webkit\.WebView`), regexp.MustCompile(`(setJavaScriptEnabled\(true\))|(.addJavascriptInterface\()`)}, NotAnd: []*regexp.Regexp{regexp.MustCompile(`webkit\.WebView`)},
		CWE:           "CWE-749",
		AverageCVSS:   8.8,
		Description:   "Insecure WebView implementation. User-controlled code execution is a security hole.",
		Recomendation: "",
	},

	Rule{
		Or:            []*regexp.Regexp{regexp.MustCompile(`content\.ClipboardManager`), regexp.MustCompile(`CLIPBOARD_SERVICE`), regexp.MustCompile(`ClipboardManager`)},
		CWE:           "CWE-200",
		AverageCVSS:   5,
		Description:   "The classes in this file write or read data on the Clipboard. The transfer area is shared between all apps so attention is needed to data that is placed in this resource.",
		Recomendation: "",
	},

	Rule{
		Or:            []*regexp.Regexp{regexp.MustCompile(`net\.JarURLConnection`), regexp.MustCompile(`JarURLConnection`), regexp.MustCompile(`jar:((?:http|https)://(?:[\w_-]+(?:(?:\.[\w_-]+)+))(?:[\w.,@?^=%&:/~+#-]*[\w@?^=%&/~+#-])?)`)},
		CWE:           "CWE-611",
		AverageCVSS:   5,
		Description:   "This code uses jar url, this functionality could generate an XML vulnerability External Entities (XXE), XXE is listed as fourth place (A4) in the Top 10 OWASP 2017",
		Recomendation: "It is recommended to avoid using url jar when possible, there are other safer methods that can be used to consult the jar file.",
	},

	Rule{
		And: []*regexp.Regexp{regexp.MustCompile(`\.crypto\.Cipher`), regexp.MustCompile(`Cipher\.getInstance\(`), regexp.MustCompile(`"AES"`)}, NotAnd: []*regexp.Regexp{regexp.MustCompile(`\.crypto\.Cipher`)},
		CWE:           "CWE-326",
		AverageCVSS:   5,
		Description:   "DES is a hash algorithm that is considered weak and can cause hash collisions.",
		Recomendation: "It is always recommended to use some CHF (Cryptographic Hash Function), which is mathematically strong and not reversible. SHA512 would be the most recommended hash for storing the password and it is also important to adopt some type of Salt, so that the Hash is more secure.",
	},

	Rule{
		And: []*regexp.Regexp{regexp.MustCompile(`\.net\.ssl`), regexp.MustCompile(`TrustAllSSLSocket-Factory|AllTrustSSLSocketFactory|NonValidatingSSLSocketFactory|net\.SSLCertificateSocketFactory|ALLOW_ALL_HOSTNAME_VERIFIER|\.setDefaultHostnameVerifier\(|NullHostnameVerifier\(`)}, NotAnd: []*regexp.Regexp{regexp.MustCompile(`\.net\.ssl`)},
		CWE:           "CWE-295",
		AverageCVSS:   7.4,
		Description:   "Insecure implementation of SSL. Trusting any certificate or accepting self-signed certificates can cause a serious security breach, making the application vulnerable to MITM (Man In The Middle) attacks.",
		Recomendation: "",
	},

	Rule{
		And: []*regexp.Regexp{regexp.MustCompile(`\.loadUrl\(`), regexp.MustCompile(`webkit\.WebView`)}, NotAnd: []*regexp.Regexp{regexp.MustCompile(`webkit\.WebView`)},
		CWE:           "CWE-919",
		AverageCVSS:   5,
		Description:   "The WebView loads files from external storage. External storage files can be modified by any application.",
		Recomendation: "",
	},

	Rule{
		Or:            []*regexp.Regexp{regexp.MustCompile(`MODE_WORLD_READABLE|Context\.MODE_WORLD_READABLE`), regexp.MustCompile(`openFileOutput\(\s*".+"\s*,\s*1\s*\)`)},
		CWE:           "CWE-276",
		AverageCVSS:   4,
		Description:   "The file is 'World Readable'. Any application can read the file.",
		Recomendation: "According to official Google documentation, MODE_WORLD_READABLE mode is deprecated. It is recommended to use MODE_PRIVATE. In case your application needs to share private files with other applications, you must use a FileProvider with the attribute FLAG_GRANT_READ_URI_PERMISSION.",
	},

	Rule{
		And: []*regexp.Regexp{regexp.MustCompile(`\.crypto\.Cipher`), regexp.MustCompile(`Cipher\.getInstance\(`), regexp.MustCompile(`"ECB"`)}, NotAnd: []*regexp.Regexp{regexp.MustCompile(`\.crypto\.Cipher`)},
		CWE:           "CWE-327",
		AverageCVSS:   5.9,
		Description:   "The application uses ECB as the 'block mode' of the encryption algorithm. ECB is considered a weak cryptographic algorithm, as it results in the same cipher for identical blocks of plain text.",
		Recomendation: "Whenever possible, avoid using the ECB mode, as it is predictable and can be broken with attacks such as frequency analysis. We recommend the use of Authenticated Encription (AE) and Authenticated Encryption with Associated Data (AEAD), which ensure both the confidentiality and authenticity of the data. Some recommended modes are GCM, EAX and OCB, CBC mode can also be used in combination with HMAC message authentication.",
	},

	Rule{
		ExactMatch:    regexp.MustCompile(`Runtime\.getRuntime\(`),
		CWE:           "CWE-78",
		AverageCVSS:   9,
		Description:   "The application executes Commands directly on the Operating System. If using any user input, it must be sanitized to the maximum, cleaning any unnecessary characters. In general, it is recommended to never use calls to native commands, being recommended the JNI (Java Native Interface) for such low level operations.",
		Recomendation: "",
	},

	Rule{
		ExactMatch:    regexp.MustCompile(`setVisibility\(View\.GONE\)|setVisibility\(View\.INVISIBLE\)`),
		CWE:           "CWE-919",
		AverageCVSS:   4.3,
		Description:   "Invisible elements in the view can be used to hide data from the user, but can still be leaked.",
		Recomendation: "",
	},

	Rule{
		And: []*regexp.Regexp{regexp.MustCompile(`dalvik\.system\.PathClassLoader|dalvik\.system\.DexFile|dalvik\.system\.DexPathList|dalvik\.system\.DexClassLoader|java\.security\.ClassLoader|java\.net\.URLClassLoader|java\.security\.SecureClassLoader`), regexp.MustCompile(`loadDex|loadClass|DexClassLoader|loadDexFile`)}, NotAnd: []*regexp.Regexp{regexp.MustCompile(`dalvik\.system\.PathClassLoader|dalvik\.system\.DexFile|dalvik\.system\.DexPathList|dalvik\.system\.DexClassLoader|java\.security\.ClassLoader|java\.net\.URLClassLoader|java\.security\.SecureClassLoader`)},
		CWE:           "CWE-695",
		AverageCVSS:   4,
		Description:   "The application loads and / or manipulates Dex files (Dexloading and dynamic classes). ",
		Recomendation: "It is not recommended to use APIs with low level of manipulation as this can facilitate the injection of code within the application. If the intention is to obfuscate the code, it is always important to take care of your obfuscator settings so as not to allow the loading of static files, which can easily be replaced by a forged file.",
	},

	Rule{
		And: []*regexp.Regexp{regexp.MustCompile(`com\.fasterxml\.jackson\.databind\.ObjectMapper`), regexp.MustCompile(`\.enableDefaultTyping\(`)}, NotAnd: []*regexp.Regexp{regexp.MustCompile(`com\.fasterxml\.jackson\.databind\.ObjectMapper`)},
		CWE:           "CWE-502",
		AverageCVSS:   7.5,
		Description:   "The app uses jackson deserialization libraryDeserialization of untrusted input can result inarbitary code execution.",
		Recomendation: "",
	},

	Rule{
		ExactMatch:    regexp.MustCompile(`MODE_PRIVATE|Context\.MODE_PRIVATE`),
		CWE:           "CWE-919",
		AverageCVSS:   5,
		Description:   "App can write to App Directory. Sensitive Information should be encrypted.",
		Recomendation: "",
	},

	Rule{
		Or:            []*regexp.Regexp{regexp.MustCompile(`com\.noshufou\.android\.su`), regexp.MustCompile(`com\.thirdparty\.superuser`), regexp.MustCompile(`eu\.chainfire\.supersu`), regexp.MustCompile(`com\.koushikdutta\.superuser`), regexp.MustCompile(`eu\.chainfire\.`)},
		CWE:           "CWE-250",
		AverageCVSS:   7.5,
		Description:   "This application has packages to access root privileges (Super User). A Super User on the user's device can do absolutely anything, making the application very powerful and possibly facilitating malicious actions. etc.",
		Recomendation: "",
	},

	Rule{
		And:           []*regexp.Regexp{regexp.MustCompile(`WebView`), regexp.MustCompile(`loadData\(`), regexp.MustCompile(`android\.webkit`)},
		NotOr:         []*regexp.Regexp{regexp.MustCompile(`WebView`), regexp.MustCompile(`android\.webkit`)},
		CWE:           "CWE-749",
		AverageCVSS:   8,
		Description:   "WebView request via GET. The Android WebViews API is very sensitive because it allows resources coming from the network to access data only available in the context of the application, making it easier for an attacker to execute Remote Code Execution, it is always necessary to ensure that the content sources presented in WebViews are encrypted and protected and user inputs are always sanitized.",
		Recomendation: "",
	},

	Rule{
		ExactMatch:    regexp.MustCompile(`Log\.(v|d|i|w|e|f|s)|System\.out\.print|System\.err\.print`),
		CWE:           "CWE-532",
		AverageCVSS:   3.2,
		Description:   "The App logs information. Sensitive information should not be logged.",
		Recomendation: "",
	},

	Rule{
		And: []*regexp.Regexp{regexp.MustCompile(`java\.util\.Random`), regexp.MustCompile(`Random\(\)`)}, NotAnd: []*regexp.Regexp{regexp.MustCompile(`java\.util\.Random`)},
		CWE:           "CWE-330",
		AverageCVSS:   1,
		Description:   "The application uses a predictable, therefore insecure, random number generator.",
		Recomendation: "Instances of java.util.Random are not cryptographically secure. Consider instead using SecureRandom to get a cryptographically secure pseudo-random number generator for use by security-sensitive applications.  https://docs.oracle.com/javase/8/docs/api/java/util/Random.html",
	},

	Rule{
		ExactMatch:    regexp.MustCompile(`Random\..*\(.*\)|Random\(.*\)|\(.*\).random\(\)`),
		CWE:           "CWE-330",
		AverageCVSS:   1,
		Description:   "The application uses a predictable, therefore insecure, random number generator.",
		Recomendation: "Instances of java.util.Random are not cryptographically secure. Consider instead using SecureRandom to get a cryptographically secure pseudo-random number generator for use by security-sensitive applications. https://docs.oracle.com/javase/8/docs/api/java/util/Random.html",
	},

	Rule{
		And: []*regexp.Regexp{regexp.MustCompile(`\.crypto\.Cipher`), regexp.MustCompile(`Cipher\.getInstance\(`), regexp.MustCompile(`"GCM"`)}, NotAnd: []*regexp.Regexp{regexp.MustCompile(`\.crypto\.Cipher`)},
		CWE:           "CWE-326",
		AverageCVSS:   2,
		Description:   "The application uses GCM as the 'block mode' of the encryption algorithm. GCM is considered a secure cryptographic algorithm as long as each encrypted block is indistinguishable from a random permutation, otherwise, it would only increase the value of IV (Initialization Vector) by 1, so the keys become predictable, when analyzing a block with a sufficient number of messages encrypted with the same key and / or IV. It may be vulnerable to 'Stream Cipher Attack'.",
		Recomendation: "Security depends on choosing a unique initialization vector (IV) for each encryption performed with the same key.",
	},

	Rule{
		ExactMatch:    regexp.MustCompile(`MessageDigest\.getInstance\("*SHA-1"*\)|MessageDigest\.getInstance\("*sha-1"*\)|DigestUtils\.sha\(`),
		CWE:           "CWE-327",
		AverageCVSS:   5.9,
		Description:   "SHA-1 is a hash algorithm considered weak and can return the same result for two different contents, which can cause collisions and in extreme cases it can cause a security breach. https://en.wikipedia.org/wiki/Collision_resistance",
		Recomendation: "It is recommended to use some CHF (Cryptographic Hash Function), which is mathematically strong and not reversible. SHA512 would be the most recommended hash for storing the password and it is also important to adopt some type of Salt, so that the Hash is more secure.",
	},
}
