package models

// PlistPermission holds data about how the app will use certain permissions
type PlistPermission struct {
	Name  string `json:"name"`
	Usage string `json:"usage"`
}

// ATSDomain is a domain put in the exceptions settings for App Transport Security
type ATSDomain struct {
	Name                    string `json:"name"`
	RequiresFowardSecrecy   bool   `json:"requiresFowardSecrecy"`  // NSExceptionRequiresForwardSecrecy
	IncludesSubdomains      bool   `json:"includesSubdomains"`     // NSIncludesSubdomains
	AllowsInsecureHTTPLoads bool   `json:"allowInsecureHTTPLoads"` // NSTemporaryExceptionAllowsInsecureHTTPLoads
}

// ATS holds data about rules in the ATS section
type ATS struct {
	AllowArbitraryLoads bool        `json:"arbitraryLoads"`   // NSAllowsArbitraryLoads
	ExceptionDomains    []ATSDomain `json:"exceptionDomains"` // NSExceptionDomains
}

// Plist structure holds data in the Property List
type Plist struct {
	Compiler        string `json:"compiler"`         // DTCompiler
	PlatformName    string `json:"platformName"`     // DTPlatformName
	PlatformBuild   string `json:"platformBuild"`    // DTPlatformBuild
	PlatformVersion string `json:"platformVersion"`  // DTPlatformVersion
	XCodeVersion    string `json:"xcodeVersion"`     // DTXcode
	XCodeBuild      string `json:"xcodeBuildNumber"` // DTXcodeBuild
	SDKName         string `json:"sdkName"`          // DTSDKName
	SDKBuild        string `json:"DTSDKBuild"`       // DTSDKBuild

	BundleName     string `json:"bundleName"`     // CFBundleName
	BundleVersion  string `json:"bundleVersion"`  // CFBundleVersion
	ExecutableName string `json:"executableName"` // CFBundleExecutable
	DisplayName    string `json:"displayName"`    // CFBundleDisplayName
	AppIdentifier  string `json:"appIdentifier"`  // CFBundleIdentifier
	PackageType    string `json:"packageType"`    // CFBundlePackageType

	MinimumOSVersion string `json:"minOSVersion"` // MinimumOSVersion

	Permissions        []PlistPermission `json:"permissions"`        // NS*UsageDescription section
	ATS                ATS               `json:"ats"`                // NSAppTransportSecurity section
	SupportedPlatforms []string          `json:"supportedPlatforms"` // CFBundleSupportedPlatforms section
}
