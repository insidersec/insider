package rule

import (
	"github.com/insidersec/insider/engine"
)

var IosRules []engine.Rule = []engine.Rule{
	Rule{
		ExactMatch:    "\\w+.withUnsafeBytes\\s*{.*",
		CWE:           "CWE-789",
		AverageCVSS:   0,
		Severity:      "Info",
		Description:   "Using this implementation of '.withUnsafeBytes' can lead to the compiler's decision to use unsafe APIs, such as _malloc and _strcpy, as the method calls closing with an UnsafeRawBufferPointer.",
		Recomendation: "Whenever possible, avoid using buffers or memory pointers that do not have a valid size.",
	},

	Rule{
		ExactMatch:  "Keychain|kSecAttrAccessibleWhenUnlocked|kSecAttrAccessibleAfterFirstUnlock|SecItemAdd|SecItemUpdate|NSDataWritingFileProtectionComplete",
		AverageCVSS: 0,
		Severity:    "Info",
		Description: "Local File I/O Operations.",
	},

	Rule{
		ExactMatch:  "UIWebView",
		AverageCVSS: 0,
		Severity:    "Info",
		Description: "WebView Component.",
	},

	Rule{
		ExactMatch:  "RNEncryptor|RNDecryptor|AESCrypt",
		AverageCVSS: 0,
		Severity:    "Info",
		Description: "Encryption API.",
	},

	Rule{
		ExactMatch:  "PDKeychainBindings",
		AverageCVSS: 0,
		Severity:    "Info",
		Description: "Keychain Access.",
	},

	Rule{
		AndExpressions: []string{"loadRequest", "webView"},
		AverageCVSS:    0,
		Severity:       "Info",
		Description:    "WebView Load Request.",
	},

	Rule{
		AndExpressions: []string{"NSHTTPCookieStorage", "sharedHTTPCookieStorage"},
		AverageCVSS:    0,
		Severity:       "Info",
		Description:    "Cookie Storage.",
	},

	Rule{
		AndExpressions: []string{"UIPasteboard", "generalPasteboard"},
		AverageCVSS:    0,
		Severity:       "Info",
		Description:    "Set or Read Clipboard",
	},

	Rule{
		ExactMatch:    "(strcpy)|(memcpy)|(strcat)|(strncat)|(strncpy)|(sprintf)|(vsprintf)",
		CWE:           "CWE-676",
		AverageCVSS:   2.2,
		Severity:      "High",
		Description:   "The application may contain prohibited APIs. These APIs are insecure and should not be used.",
		Recomendation: "Avoid using unsafe API (s) and never rely on data entered by the user, always sanitize the data entered.",
	},

	Rule{
		ExactMatch:    "canAuthenticateAgainstProtectionSpace|continueWithoutCredentialForAuthenticationChallenge|kCFStreamSSLAllowsExpiredCertificates|kCFStreamSSLAllowsAnyRoot|kCFStreamSSLAllowsExpiredRoots|validatesSecureCertificate\\s*=\\s*(no|NO)|allowInvalidCertificates\\s*=\\s*(YES|yes)",
		CWE:           "CWE-295",
		AverageCVSS:   7.4,
		Severity:      "High",
		Description:   "The application allows self-signed or invalid SSL certificates. The application is vulnerable to MITM (Man-In-The-Middle) attacks.",
		Recomendation: "Certificates must be carefully managed and verified to ensure that data is encrypted with the intended owner's public key.",
	},

	Rule{
		ExactMatch:    "setAllowsAnyHTTPSCertificate:\\s*YES|allowsAnyHTTPSCertificateForHost|loadingUnvalidatedHTTPSPage\\s*=\\s*(YES|yes)",
		CWE:           "CWE-295",
		AverageCVSS:   7.4,
		Severity:      "High",
		Description:   "The in-app UIWebView ignores SSL errors and accepts any SSL certificate. The application is vulnerable to attacks from MITM (Man-In-The-Middle).",
		Recomendation: "Certificates must be carefully managed and verified to ensure that data is encrypted with the intended owner's public key.",
	},

	Rule{
		ExactMatch:    "NSLog|NSAssert|fprintf|fprintf|Logging",
		CWE:           "CWE-532",
		AverageCVSS:   0,
		Severity:      "Info",
		Description:   "The binary can use the NSLog function for logging. Confidential information should never be recorded.",
		Recomendation: "Prevent sensitive data from being logged into production.",
	},

	Rule{
		ExactMatch:  "UIPasteboardChangedNotification|generalPasteboard\\]\\.string",
		AverageCVSS: 0,
		Severity:    "Info",
		Description: "The application allows you to list the changes on the Clipboard. Some malware also lists changes to the Clipboard.",
	},

	Rule{
		ExactMatch:  "sqlite3_exec",
		AverageCVSS: 0,
		Severity:    "Info",
		Description: "The application is using SQLite. Confidential information must be encrypted",
	},

	Rule{
		ExactMatch:  "NSTemporaryDirectory\\(\\),",
		CWE:         "CWE-22",
		AverageCVSS: 7.5,
		Severity:    "Info",
		Description: "User use in \"NSTemporaryDirectory ()\" is unreliable, it can result in vulnerabilities in the directory.",
	},

	Rule{
		AndExpressions: []string{"loadHTMLString", "webView"},
		CWE:            "CWE-95",
		AverageCVSS:    8.8,
		Severity:       "Info",
		Description:    "User input not sanitized in 'loadHTMLString' can result in an injection of JavaScript in the context of your application, allowing access to private data.",
	},

	Rule{
		AndExpressions: []string{"SFAntiPiracy.h", "SFAntiPiracy", "isJailbroken"},
		AverageCVSS:    0,
		Severity:       "Info",
		Description:    "Verificações SFAntiPiracy Jailbreak encontradas",
	},

	Rule{
		AndExpressions: []string{"SFAntiPiracy.h", "SFAntiPiracy", "isPirated"},
		AverageCVSS:    0,
		Severity:       "Info",
		Description:    "Verificações SFAntiPiracy Jailbreak encontradas",
	},

	Rule{
		AndExpressions: []string{"CommonDigest.h", "CC_MD5"},
		CWE:            "CWE-327",
		AverageCVSS:    7.4,
		Severity:       "High",
		Description:    "MD5 is a weak hash, which can generate repeated hashes.",
		Recomendation:  "When it is necessary to store or transmit sensitive data, give preference to modern encryption algorithms and check frequently that the algorithm used has not become obsolete.",
	},

	Rule{
		AndExpressions: []string{"CommonDigest.h", "CC_SHA1"},
		CWE:            "CWE-327",
		AverageCVSS:    5.9,
		Severity:       "High",
		Description:    "SHA1 is a weak hash, which can generate repeated hashes.",
		Recomendation:  "When it is necessary to store or transmit sensitive data, give preference to modern encryption algorithms and check frequently that the algorithm used has not become obsolete.",
	},

	Rule{
		AndExpressions: []string{"kCCOptionECBMode", "kCCAlgorithmAES"},
		CWE:            "CWE-327",
		AverageCVSS:    5.9,
		Severity:       "High",
		Description:    "The application uses ECB mode in the encryption algorithm. It is known that the ECB mode is weak, as it results in the same ciphertext for identical blocks of plain text.",
		Recomendation:  "When it is necessary to store or transmit sensitive data, give preference to modern encryption algorithms and check frequently that the algorithm used has not become obsolete.",
	},

	Rule{
		AndExpressions: []string{"ptrace_ptr", "PT_DENY_ATTACH"},
		AverageCVSS:    0,
		Severity:       "Info",
		Description:    "The application has anti-debugger using ptrace ()",
	},

	Rule{
		AndExpressions: []string{"mach/mach_init.h", "MACH_PORT_VALID|mach_task_self\\(\\)"},
		AverageCVSS:    0,
		Severity:       "Info",
		Description:    "The application has anti-debugger using Mach Exception Ports.",
	},

	Rule{
		ExactMatch:  "(\\w+\\s*=\\s*UIPasteboard)",
		AverageCVSS: 0,
		Severity:    "Info",
		Description: "The application copies data to the Clipboard. Confidential data must not be copied to the Clipboard, as other applications can access it.",
	},

	Rule{
		OrExpressions: []string{"/Applications/Cydia.app",
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
			"frida-server"},
		AverageCVSS: 0,
		Severity:    "Info",
		Description: "The application may contain Jailbreak detection mechanisms.",
	},
}
