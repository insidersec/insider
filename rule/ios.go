package rule

import (
	"regexp"

	"github.com/insidersec/insider/engine"
)

var IosRules []engine.Rule = []engine.Rule{

	Rule{
		ExactMatch:    regexp.MustCompile(`NSTemporaryDirectory\(\),`),
		CWE:           "CWE-22",
		AverageCVSS:   7.5,
		Description:   `User use in "NSTemporaryDirectory ()" is unreliable, it can result in vulnerabilities in the directory.`,
		Recomendation: "",
	},

	Rule{
		ExactMatch:    regexp.MustCompile(`\w+.withUnsafeBytes\s*{.*`),
		CWE:           "CWE-789",
		AverageCVSS:   4,
		Description:   "Using this implementation of '.withUnsafeBytes' can lead to the compiler's decision to use unsafe APIs, such as _malloc and _strcpy, as the method calls closing with an UnsafeRawBufferPointer.",
		Recomendation: "Whenever possible, avoid using buffers or memory pointers that do not have a valid size.",
	},

	Rule{
		ExactMatch:    regexp.MustCompile(`canAuthenticateAgainstProtectionSpace|continueWithoutCredentialForAuthenticationChallenge|kCFStreamSSLAllowsExpiredCertificates|kCFStreamSSLAllowsAnyRoot|kCFStreamSSLAllowsExpiredRoots|validatesSecureCertificate\s*=\s*(no|NO)|allowInvalidCertificates\s*=\s*(YES|yes)`),
		CWE:           "CWE-295",
		AverageCVSS:   7.4,
		Description:   "The application allows self-signed or invalid SSL certificates. The application is vulnerable to MITM (Man-In-The-Middle) attacks.",
		Recomendation: "Certificates must be carefully managed and verified to ensure that data is encrypted with the intended owner's public key.",
	},

	Rule{
		ExactMatch:    regexp.MustCompile(`setAllowsAnyHTTPSCertificate:\s*YES|allowsAnyHTTPSCertificateForHost|loadingUnvalidatedHTTPSPage\s*=\s*(YES|yes)`),
		CWE:           "CWE-295",
		AverageCVSS:   7.4,
		Description:   "The in-app UIWebView ignores SSL errors and accepts any SSL certificate. The application is vulnerable to attacks from MITM (Man-In-The-Middle).",
		Recomendation: "Certificates must be carefully managed and verified to ensure that data is encrypted with the intended owner's public key.",
	},

	Rule{
		ExactMatch:    regexp.MustCompile(`kSecAttrAccessibleWhenUnlocked|kSecAttrAccessibleAfterFirstUnlock|SecItemAdd|SecItemUpdate|NSDataWritingFileProtectionComplete`),
		CWE:           "CWE-695",
		AverageCVSS:   5,
		Description:   "Local File I/O Operations.",
		Recomendation: "",
	},

	Rule{
		And: []*regexp.Regexp{regexp.MustCompile(`loadRequest`), regexp.MustCompile(`WebView`)}, NotAnd: []*regexp.Regexp{regexp.MustCompile(`WebView`)},
		CWE:           "CWE-749",
		AverageCVSS:   5,
		Description:   "WebView Load Request.",
		Recomendation: "",
	},

	Rule{
		And: []*regexp.Regexp{regexp.MustCompile(`NSHTTPCookieStorage`), regexp.MustCompile(`sharedHTTPCookieStorage`)}, NotAnd: []*regexp.Regexp{regexp.MustCompile(`NSHTTPCookieStorage`)},
		CWE:           "CWE-539",
		AverageCVSS:   5.3,
		Description:   "Cookie Storage.",
		Recomendation: "",
	},

	Rule{
		And: []*regexp.Regexp{regexp.MustCompile(`CommonDigest.h`), regexp.MustCompile(`CC_MD5`)}, NotAnd: []*regexp.Regexp{regexp.MustCompile(`CommonDigest.h`)},
		CWE:           "CWE-327",
		AverageCVSS:   7.4,
		Description:   "MD5 is a weak hash, which can generate repeated hashes.",
		Recomendation: "When it is necessary to store or transmit sensitive data, give preference to modern encryption algorithms and check frequently that the algorithm used has not become obsolete.",
	},

	Rule{
		ExactMatch:    regexp.MustCompile(`UIPasteboard.`),
		CWE:           "CWE-200",
		AverageCVSS:   9.8,
		Description:   "The application copies data to the UIPasteboard. Confidential data must not be copied to the UIPasteboard, as other applications can access it.",
		Recomendation: "",
	},

	Rule{
		And: []*regexp.Regexp{regexp.MustCompile(`loadHTMLString\(`), regexp.MustCompile(`WKWebView`)}, NotAnd: []*regexp.Regexp{regexp.MustCompile(`WKWebView`)},
		CWE:           "CWE-95",
		AverageCVSS:   8.8,
		Description:   "User input not sanitized in 'loadHTMLString' can result in an injection of JavaScript in the context of your application, allowing access to private data.",
		Recomendation: "",
	},

	Rule{
		Or:            []*regexp.Regexp{regexp.MustCompile(`(?i)SHA1\(`), regexp.MustCompile(`CC_SHA1\(`)},
		CWE:           "CWE-327",
		AverageCVSS:   5.9,
		Description:   "SHA1 is a weak hash, which can generate repeated hashes.",
		Recomendation: "When it is necessary to store or transmit sensitive data, give preference to modern encryption algorithms and check frequently that the algorithm used has not become obsolete.",
	},

	Rule{
		And:           []*regexp.Regexp{regexp.MustCompile(`kCCOptionECBMode`), regexp.MustCompile(`kCCAlgorithmAES`)},
		CWE:           "CWE-327",
		AverageCVSS:   5.9,
		Description:   "The application uses ECB mode in the encryption algorithm. It is known that the ECB mode is weak, as it results in the same ciphertext for identical blocks of plain text.",
		Recomendation: "When it is necessary to store or transmit sensitive data, give preference to modern encryption algorithms and check frequently that the algorithm used has not become obsolete.",
	},

	Rule{
		And: []*regexp.Regexp{regexp.MustCompile(`mach/mach_init.h`), regexp.MustCompile(`MACH_PORT_VALID|mach_task_self\(\)`)}, NotAnd: []*regexp.Regexp{regexp.MustCompile(`mach/mach_init.h`)},
		CWE:           "CWE-215",
		AverageCVSS:   5,
		Description:   "The application has anti-debugger using Mach Exception Ports.",
		Recomendation: "",
	},

	Rule{
		Or:            []*regexp.Regexp{regexp.MustCompile(`CC_MD4_Init|CC_MD4_Update|CC_MD4_Final|CC_MD4|MD4_Init`), regexp.MustCompile(`MD4_Update|MD4_Final|CC_MD5_Init|CC_MD5_Update|CC_MD5_Final|CC_MD5|MD5_Init`), regexp.MustCompile(`MD5_Update|MD5_Final|MD5Init|MD5Update|MD5Final`)},
		CWE:           "CWE-327",
		AverageCVSS:   5.9,
		Description:   "The app is using weak encryption APIs and / or that are known to have hash conflicts.",
		Recomendation: "",
	},

	Rule{
		Or:            []*regexp.Regexp{regexp.MustCompile(`(?i)MD2\(`), regexp.MustCompile(`CC_MD2\(`)},
		CWE:           "CWE-327",
		AverageCVSS:   5.9,
		Description:   "MD2 is a weak hash known to have hash collisions.",
		Recomendation: "",
	},

	Rule{
		Or:            []*regexp.Regexp{regexp.MustCompile(`(?i)MD6\(`), regexp.MustCompile(`CC_MD6\(`)},
		CWE:           "CWE-327",
		AverageCVSS:   5.9,
		Description:   "MD6 is a weak hash known to have hash collisions.",
		Recomendation: "",
	},

	Rule{
		Or:            []*regexp.Regexp{regexp.MustCompile(`/Applications/Cydia.app`), regexp.MustCompile(`/Library/MobileSubstrate/MobileSubstrate.dylib`), regexp.MustCompile(`/usr/sbin/sshd`), regexp.MustCompile(`/etc/apt`), regexp.MustCompile(`cydia://`), regexp.MustCompile(`/var/lib/cydia`), regexp.MustCompile(`/Applications/FakeCarrier.app`), regexp.MustCompile(`/Applications/Icy.app`), regexp.MustCompile(`/Applications/IntelliScreen.app`), regexp.MustCompile(`/Applications/SBSettings.app`), regexp.MustCompile(`/Library/MobileSubstrate/DynamicLibraries/LiveClock.plist`), regexp.MustCompile(`/System/Library/LaunchDaemons/com.ikey.bbot.plist`), regexp.MustCompile(`/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist`), regexp.MustCompile(`/etc/ssh/sshd_config`), regexp.MustCompile(`/private/var/tmp/cydia.log`), regexp.MustCompile(`/usr/libexec/ssh-keysign`), regexp.MustCompile(`/Applications/MxTube.app`), regexp.MustCompile(`/Applications/RockApp.app`), regexp.MustCompile(`/Applications/WinterBoard.app`), regexp.MustCompile(`/Applications/blackra1n.app`), regexp.MustCompile(`/Library/MobileSubstrate/DynamicLibraries/Veency.plist`), regexp.MustCompile(`/private/var/lib/apt`), regexp.MustCompile(`/private/var/lib/cydia`), regexp.MustCompile(`/private/var/mobile/Library/SBSettings/Themes`), regexp.MustCompile(`/private/var/stash`), regexp.MustCompile(`/usr/bin/sshd`), regexp.MustCompile(`/usr/libexec/sftp-server`), regexp.MustCompile(`/var/cache/apt`), regexp.MustCompile(`/var/lib/apt`), regexp.MustCompile(`/usr/sbin/frida-server`), regexp.MustCompile(`/usr/bin/cycript`), regexp.MustCompile(`/usr/local/bin/cycript`), regexp.MustCompile(`/usr/lib/libcycript.dylib`), regexp.MustCompile(`frida-server`)},
		CWE:           "CWE-693",
		AverageCVSS:   0,
		Description:   "The application may contain Jailbreak detection mechanisms.",
		Recomendation: "",
	},

	Rule{
		And:           []*regexp.Regexp{regexp.MustCompile(`UIPasteboard\(`), regexp.MustCompile(`.generalPasteboard`)},
		CWE:           "CWE-200",
		AverageCVSS:   5,
		Description:   "Set or Read Clipboard",
		Recomendation: "",
	},

	Rule{
		ExactMatch:    regexp.MustCompile(`UIPasteboardChangedNotification|generalPasteboard\]\.string`),
		CWE:           " CWE-200",
		AverageCVSS:   5,
		Description:   "The application allows you to list the changes on the Clipboard. Some malware also lists changes to the Clipboard.",
		Recomendation: "",
	},

	Rule{
		Or:            []*regexp.Regexp{regexp.MustCompile(`sqlite3_exec`), regexp.MustCompile(`sqlite3_finalize`)},
		CWE:           "CWE-922",
		AverageCVSS:   5.5,
		Description:   "The application is using SQLite. Confidential information must be encrypted",
		Recomendation: "",
	},

	Rule{
		And: []*regexp.Regexp{regexp.MustCompile(`NSLog\(|NSAssert\(|fprintf\(|fprintf\(|Logging\(`)}, NotAnd: []*regexp.Regexp{regexp.MustCompile(`\*`)},
		CWE:           "CWE-532",
		AverageCVSS:   7.5,
		Description:   "The binary can use the NSLog function for logging. Confidential information should never be recorded.",
		Recomendation: "Prevent sensitive data from being logged into production.",
	},

	Rule{
		ExactMatch:    regexp.MustCompile(`(?i)\.noFileProtection`),
		CWE:           "CWE-311",
		AverageCVSS:   4.3,
		Description:   "The file has no special protections associated with it.",
		Recomendation: "",
	},

	Rule{
		And:           []*regexp.Regexp{regexp.MustCompile(`\.TLSMinimumSupportedProtocolVersion`), regexp.MustCompile(`tls_protocol_version_t\.TLSv10|tls_protocol_version_t\.TLSv11`)},
		CWE:           "CWE-757",
		AverageCVSS:   7.5,
		Description:   "TLS 1.3 should be used. Detected old version.",
		Recomendation: "",
	},

	Rule{
		And:           []*regexp.Regexp{regexp.MustCompile(`\.TLSMinimumSupportedProtocolVersion`), regexp.MustCompile(`tls_protocol_version_t\.TLSv12`)},
		CWE:           "",
		AverageCVSS:   0,
		Description:   "TLS 1.3 should be used. Detected old version - TLS 1.2.",
		Recomendation: "",
	},

	Rule{
		ExactMatch:    regexp.MustCompile(`strcpy\(|memcpy\(|strcat\(|strncat\(|strncpy\(|sprintf\(|vsprintf\(|gets\(`),
		CWE:           "CWE-676",
		AverageCVSS:   2.2,
		Description:   "The application may contain prohibited APIs. These APIs are insecure and should not be used.",
		Recomendation: "Avoid using unsafe API (s) and never rely on data entered by the user, always sanitize the data entered.",
	},

	Rule{
		ExactMatch:    regexp.MustCompile(`NSFileProtectionNone`),
		CWE:           "CWE-311",
		AverageCVSS:   4.3,
		Description:   "The file has no special protections associated with it.",
		Recomendation: "",
	},
}
