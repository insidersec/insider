package models

// Permission is a AndroidManifest permission entry
type Permission struct {
	Name     string `xml:"name,attr"`
	Required string `xml:"required,attr"`
}

// SDKInfo is the AndroidManifest informative entry
type SDKInfo struct {
	MinimumSDKVersion string `xml:"minSdkVersion,attr"`
	TargetSDKVersion  string `xml:"targetSdkVersion,attr"`
	MaximumSDKVersion string `xml:"maxSdkVersion,attr"`
}

// IntentAction represents a Action for the Android Activity.
type IntentAction struct {
	Name string `xml:"name,attr"`
}

// IntentCategory holds data about the Activity category.
type IntentCategory struct {
	Name string `xml:"name,attr"`
}

// IntentFilter holds metadata about the `intention-filter` tag for the given Activity.
type IntentFilter struct {
	Actions    []IntentAction `xml:"action"`
	Categories IntentCategory `xml:"category"`
}

// ManifestActivity holds data from the `activities` tag in the AndroidManifest.xml file
type ManifestActivity struct {
	Name         string       `xml:"name,attr"`
	IntentFilter IntentFilter `xml:"intent-filter"`
}

// BroadcastReceiver holds data about a broadcast receiver entry in AndroidManifest.xml
type BroadcastReceiver struct {
	Name       string `xml:"name,attr"`
	Enabled    string `xml:"enabled,attr"`
	IsExported string `xml:"exported,attr"`
	Permission string `xml:"permission,attr"`
}

// Service holds data about a Android Service entry in AndroidManifest.xml file
type Service struct {
	Name       string `xml:"name,attr"`
	IsExported string `xml:"exported,attr"`
	Permission string `xml:"permission,attr"`
}

// ApplicationInfo holds app data from AndroidManifest.xml
type ApplicationInfo struct {
	Name               string              `xml:"name,attr"`
	AllowADBBackup     string              `xml:"allowBackup,attr"`
	Activities         []ManifestActivity  `xml:"activity"`
	BroadcastReceivers []BroadcastReceiver `xml:"receiver"`
	Services           []Service           `xml:"service"`
}

// Manifest holds all the data about the AndroidManifest file
type Manifest struct {
	PackageName string          `xml:"package,attr"`
	Permissions []Permission    `xml:"uses-permission"`
	SDKInfo     SDKInfo         `xml:"uses-sdk"`
	Application ApplicationInfo `xml:"application"`

	// Info section
	VersionName            string `xml:"versionName,attr"`
	VersionCode            string `xml:"versionCode,attr"`
	CompiledSDKVersion     string `xml:"compileSdkVersion,attr"`
	CompiledSDKVersionCode string `xml:"compileSdkVersionCodename,attr"`
	PlatformVersionName    string `xml:"platformBuildVersionName,attr"`
	PlatformVersionCode    string `xml:"platformBuildVersionCode,attr"`
}
