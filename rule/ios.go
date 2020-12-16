package rule

import (
	"regexp"

	"github.com/insidersec/insider/engine"
)

var IosRules []engine.Rule = []engine.Rule{
	Rule{
		ExactMatch:    regexp.MustCompile(`\w+.withUnsafeBytes\s*{.*`),
		CWE:           "CWE-789",
		AverageCVSS:   0,
		Severity:      "Info",
		Description:   "Using this implementation of '.withUnsafeBytes' can lead to the compiler's decision to use unsafe APIs, such as _malloc and _strcpy, as the method calls closing with an UnsafeRawBufferPointer.",
		Recomendation: "Whenever possible, avoid using buffers or memory pointers that do not have a valid size.",
	},

	Rule{
		ExactMatch:  regexp.MustCompile("Keychain|kSecAttrAccessibleWhenUnlocked|kSecAttrAccessibleAfterFirstUnlock|SecItemAdd|SecItemUpdate|NSDataWritingFileProtectionComplete"),
		AverageCVSS: 0,
		Severity:    "Info",
		Description: "Local File I/O Operations.",
	},

	Rule{
		ExactMatch:  regexp.MustCompile("UIWebView"),
		AverageCVSS: 0,
		Severity:    "Info",
		Description: "WebView Component.",
	},

	Rule{
		ExactMatch:  regexp.MustCompile("RNEncryptor|RNDecryptor|AESCrypt"),
		AverageCVSS: 0,
		Severity:    "Info",
		Description: "Encryption API.",
	},

	Rule{
		ExactMatch:  regexp.MustCompile("PDKeychainBindings"),
		AverageCVSS: 0,
		Severity:    "Info",
		Description: "Keychain Access.",
	},

	Rule{
		And:         []*regexp.Regexp{regexp.MustCompile("loadRequest"), regexp.MustCompile("webView")},
		AverageCVSS: 0,
		Severity:    "Info",
		Description: "WebView Load Request.",
	},

	Rule{
		And:         []*regexp.Regexp{regexp.MustCompile("NSHTTPCookieStorage"), regexp.MustCompile("sharedHTTPCookieStorage")},
		AverageCVSS: 0,
		Severity:    "Info",
		Description: "Cookie Storage.",
	},

	Rule{
		And:         []*regexp.Regexp{regexp.MustCompile("UIPasteboard"), regexp.MustCompile("generalPasteboard")},
		AverageCVSS: 0,
		Severity:    "Info",
		Description: "Set or Read Clipboard",
	},

	Rule{
		ExactMatch:    regexp.MustCompile("(strcpy)|(memcpy)|(strcat)|(strncat)|(strncpy)|(sprintf)|(vsprintf)"),
		CWE:           "CWE-676",
		AverageCVSS:   2.2,
		Severity:      "High",
		Description:   "The application may contain prohibited APIs. These APIs are insecure and should not be used.",
		Recomendation: "Avoid using unsafe API (s) and never rely on data entered by the user, always sanitize the data entered.",
	},

	Rule{
		ExactMatch:    regexp.MustCompile(`canAuthenticateAgainstProtectionSpace|continueWithoutCredentialForAuthenticationChallenge|kCFStreamSSLAllowsExpiredCertificates|kCFStreamSSLAllowsAnyRoot|kCFStreamSSLAllowsExpiredRoots|validatesSecureCertificate\s*=\s*(no|NO)|allowInvalidCertificates\s*=\s*(YES|yes)`),
		CWE:           "CWE-295",
		AverageCVSS:   7.4,
		Severity:      "High",
		Description:   "The application allows self-signed or invalid SSL certificates. The application is vulnerable to MITM (Man-In-The-Middle) attacks.",
		Recomendation: "Certificates must be carefully managed and verified to ensure that data is encrypted with the intended owner's public key.",
	},

	Rule{
		ExactMatch:    regexp.MustCompile(`setAllowsAnyHTTPSCertificate:\s*YES|allowsAnyHTTPSCertificateForHost|loadingUnvalidatedHTTPSPage\s*=\s*(YES|yes)`),
		CWE:           "CWE-295",
		AverageCVSS:   7.4,
		Severity:      "High",
		Description:   "The in-app UIWebView ignores SSL errors and accepts any SSL certificate. The application is vulnerable to attacks from MITM (Man-In-The-Middle).",
		Recomendation: "Certificates must be carefully managed and verified to ensure that data is encrypted with the intended owner's public key.",
	},

	Rule{
		ExactMatch:    regexp.MustCompile("NSLog|NSAssert|fprintf|fprintf|Logging"),
		CWE:           "CWE-532",
		AverageCVSS:   0,
		Severity:      "Info",
		Description:   "The binary can use the NSLog function for logging. Confidential information should never be recorded.",
		Recomendation: "Prevent sensitive data from being logged into production.",
	},

	Rule{
		ExactMatch:  regexp.MustCompile(`UIPasteboardChangedNotification|generalPasteboard\]\.string`),
		AverageCVSS: 0,
		Severity:    "Info",
		Description: "The application allows you to list the changes on the Clipboard. Some malware also lists changes to the Clipboard.",
	},

	Rule{
		ExactMatch:  regexp.MustCompile("sqlite3_exec"),
		AverageCVSS: 0,
		Severity:    "Info",
		Description: "The application is using SQLite. Confidential information must be encrypted",
	},

	Rule{
		ExactMatch:  regexp.MustCompile(`NSTemporaryDirectory\(\),`),
		CWE:         "CWE-22",
		AverageCVSS: 7.5,
		Severity:    "Info",
		Description: `User use in "NSTemporaryDirectory ()" is unreliable, it can result in vulnerabilities in the directory.`,
	},

	Rule{
		And:         []*regexp.Regexp{regexp.MustCompile("loadHTMLString"), regexp.MustCompile("webView")},
		CWE:         "CWE-95",
		AverageCVSS: 8.8,
		Severity:    "Info",
		Description: "User input not sanitized in 'loadHTMLString' can result in an injection of JavaScript in the context of your application, allowing access to private data.",
	},

	Rule{
		And:         []*regexp.Regexp{regexp.MustCompile("SFAntiPiracy.h"), regexp.MustCompile("SFAntiPiracy"), regexp.MustCompile("isJailbroken")},
		AverageCVSS: 0,
		Severity:    "Info",
		Description: "Verificações SFAntiPiracy Jailbreak encontradas",
	},

	Rule{
		And:         []*regexp.Regexp{regexp.MustCompile("SFAntiPiracy.h"), regexp.MustCompile("SFAntiPiracy"), regexp.MustCompile("isPirated")},
		AverageCVSS: 0,
		Severity:    "Info",
		Description: "Verificações SFAntiPiracy Jailbreak encontradas",
	},

	Rule{
		And:           []*regexp.Regexp{regexp.MustCompile("CommonDigest.h"), regexp.MustCompile("CC_MD5")},
		CWE:           "CWE-327",
		AverageCVSS:   7.4,
		Severity:      "High",
		Description:   "MD5 is a weak hash, which can generate repeated hashes.",
		Recomendation: "When it is necessary to store or transmit sensitive data, give preference to modern encryption algorithms and check frequently that the algorithm used has not become obsolete.",
	},

	Rule{
		And:           []*regexp.Regexp{regexp.MustCompile("CommonDigest.h"), regexp.MustCompile("CC_SHA1")},
		CWE:           "CWE-327",
		AverageCVSS:   5.9,
		Severity:      "High",
		Description:   "SHA1 is a weak hash, which can generate repeated hashes.",
		Recomendation: "When it is necessary to store or transmit sensitive data, give preference to modern encryption algorithms and check frequently that the algorithm used has not become obsolete.",
	},

	Rule{
		And:           []*regexp.Regexp{regexp.MustCompile("kCCOptionECBMode"), regexp.MustCompile("kCCAlgorithmAES")},
		CWE:           "CWE-327",
		AverageCVSS:   5.9,
		Severity:      "High",
		Description:   "The application uses ECB mode in the encryption algorithm. It is known that the ECB mode is weak, as it results in the same ciphertext for identical blocks of plain text.",
		Recomendation: "When it is necessary to store or transmit sensitive data, give preference to modern encryption algorithms and check frequently that the algorithm used has not become obsolete.",
	},

	Rule{
		And:         []*regexp.Regexp{regexp.MustCompile("ptrace_ptr"), regexp.MustCompile("PT_DENY_ATTACH")},
		AverageCVSS: 0,
		Severity:    "Info",
		Description: "The application has anti-debugger using ptrace ()",
	},

	Rule{
		And:         []*regexp.Regexp{regexp.MustCompile("mach/mach_init.h"), regexp.MustCompile(`MACH_PORT_VALID|mach_task_self\(\)`)},
		AverageCVSS: 0,
		Severity:    "Info",
		Description: "The application has anti-debugger using Mach Exception Ports.",
	},

	Rule{
		ExactMatch:  regexp.MustCompile(`(\w+\s*=\s*UIPasteboard)`),
		AverageCVSS: 0,
		Severity:    "Info",
		Description: "The application copies data to the Clipboard. Confidential data must not be copied to the Clipboard, as other applications can access it.",
	},

	Rule{
		Or: []*regexp.Regexp{
			regexp.MustCompile("/Applications/Cydia.app"),
			regexp.MustCompile("/Library/MobileSubstrate/MobileSubstrate.dylib"),
			regexp.MustCompile("/usr/sbin/sshd"),
			regexp.MustCompile("/etc/apt"),
			regexp.MustCompile("cydia://"),
			regexp.MustCompile("/var/lib/cydia"),
			regexp.MustCompile("/Applications/FakeCarrier.app"),
			regexp.MustCompile("/Applications/Icy.app"),
			regexp.MustCompile("/Applications/IntelliScreen.app"),
			regexp.MustCompile("/Applications/SBSettings.app"),
			regexp.MustCompile("/Library/MobileSubstrate/DynamicLibraries/LiveClock.plist"),
			regexp.MustCompile("/System/Library/LaunchDaemons/com.ikey.bbot.plist"),
			regexp.MustCompile("/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist"),
			regexp.MustCompile("/etc/ssh/sshd_config"),
			regexp.MustCompile("/private/var/tmp/cydia.log"),
			regexp.MustCompile("/usr/libexec/ssh-keysign"),
			regexp.MustCompile("/Applications/MxTube.app"),
			regexp.MustCompile("/Applications/RockApp.app"),
			regexp.MustCompile("/Applications/WinterBoard.app"),
			regexp.MustCompile("/Applications/blackra1n.app"),
			regexp.MustCompile("/Library/MobileSubstrate/DynamicLibraries/Veency.plist"),
			regexp.MustCompile("/private/var/lib/apt"),
			regexp.MustCompile("/private/var/lib/cydia"),
			regexp.MustCompile("/private/var/mobile/Library/SBSettings/Themes"),
			regexp.MustCompile("/private/var/stash"),
			regexp.MustCompile("/usr/bin/sshd"),
			regexp.MustCompile("/usr/libexec/sftp-server"),
			regexp.MustCompile("/var/cache/apt"),
			regexp.MustCompile("/var/lib/apt"),
			regexp.MustCompile("/usr/sbin/frida-server"),
			regexp.MustCompile("/usr/bin/cycript"),
			regexp.MustCompile("/usr/local/bin/cycript"),
			regexp.MustCompile("/usr/lib/libcycript.dylib"),
			regexp.MustCompile("frida-server"),
		},
		AverageCVSS: 0,
		Severity:    "Info",
		Description: "The application may contain Jailbreak detection mechanisms.",
	},
}
