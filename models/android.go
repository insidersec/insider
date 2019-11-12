package models

type AndroidInfo struct {
	PackageName        string   `json:"packageName,omitempty"`
	SubPackageNames    []string `json:"subPackages,omitempty"`
	Size               string   `json:"size,omitempty"`
	TargetSDK          string   `json:"targetSdk,omitempty"`
	MinimumSDK         string   `json:"minSdk,omitempty"`
	MaximumSDK         string   `json:"maxSdk,omitempty"`
	AndroidVersionName string   `json:"androidVersionName,omitempty"`
	AndroidVersionCode string   `json:"androidVersion,omitempty"`
	MainActivity       string   `json:"mainActivity,omitempty"`
	NumberOfLines      int      `json:"numberOfLines,omitempty"`
}

type BrowsableActivity struct {
	Title           string   `json:"title,omitempty"`
	Hosts           []string `json:"hosts,omitempty"`
	MIMETypes       []string `json:"mimeTypes,omitempty"`
	CallableSchemes []string `json:"schemes,omitempty"`
}

type ManifestEntry struct {
	Title       string `json:"title,omitempty"`
	Status      string `json:"status,omitempty"`
	Description string `json:"description,omitempty"`
	Class       string `json:"class,omitempty"`
}

type Activity struct {
	Name string `json:"activity,omitempty"`
}

type Service struct {
	Name string `json:"service,omitempty"`
}

type BroadcastReceiver struct {
	Name string `json:"receiver,omitempty"`
}

type ManifestPermission struct {
	Title       string `json:"title,omitempty"`
	Status      string `json:"status,omitempty"`
	Description string `json:"description,omitempty"`
	Info        string `json:"info,omitempty"`
}

type AndroidReport struct {
	AndroidInfo             AndroidInfo          `json:"android,omitempty"`
	BrowsableActivities     []BrowsableActivity  `json:"browsableActivities,omitempty"`
	Vulnerabilities         []Vulnerability      `json:"vulnerabilities,omitempty"`
	Services                []Service            `json:"services,omitempty"`
	BroadcastReceivers      []BroadcastReceiver  `json:"receivers,omitempty"`
	AvailableActivities     []Activity           `json:"activities,omitempty"`
	Libraries               []Library            `json:"libraries,omitempty"`
	ManifestVulnerabilities []ManifestEntry      `json:"manifest,omitempty"`
	ManifestPermissions     []ManifestPermission `json:"permissions,omitempty"`
}
