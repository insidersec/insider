package reports

// AndroidInfo is all the metadata we collect from an AndroidManifest.xml file
// for our report
type AndroidInfo struct {
	SastID             string   `json:"sast,omitempty"`
	Title              string   `json:"psTitle,omitempty"`
	Score              string   `json:"psScore,omitempty"`
	InstallationCount  string   `json:"psInstalls,omitempty"`
	Categories         string   `json:"psCategory,omitempty"`
	Icon               string   `json:"psIcon,omitempty"`
	PackageName        string   `json:"packageName,omitempty"`
	SubPackageNames    []string `json:"subPackages,omitempty"`
	Size               string   `json:"size,omitempty"`
	TargetSDK          string   `json:"targetSdk,omitempty"`
	MinimumSDK         string   `json:"minSdk,omitempty"`
	MaximumSDK         string   `json:"maxSdk,omitempty"`
	AndroidVersionName string   `json:"androidVersionName,omitempty"`
	AndroidVersionCode string   `json:"androidVersion,omitempty"`
	HighestCVSS        float64  `json:"averageCvss,omitempty"`
	SecurityScore      float32  `json:"securityScore,omitempty"`
	MainActivity       string   `json:"mainActivity,omitempty"`
	MD5                string   `json:"md5,omitempty"`
	SHA256             string   `json:"sha256,omitempty"`
	SHA1               string   `json:"sha1,omitempty"`
	NumberOfLines      int      `json:"numberOfLines,omitempty"`
}

// BrowsableActivity represents a browsable activity
// entry in an AndroidManifest.xml file
// for our report
type BrowsableActivity struct {
	SastID          string   `json:"sast,omitempty"`
	Title           string   `json:"title,omitempty"`
	Hosts           []string `json:"hosts,omitempty"`
	MIMETypes       []string `json:"mimeTypes,omitempty"`
	CallableSchemes []string `json:"schemes,omitempty"`
}

// ManifestEntry represents a permission entry in an AndroidManifest.xml file
// for our report
type ManifestEntry struct {
	SastID      string `json:"sast,omitempty"`
	Title       string `json:"title,omitempty"`
	Status      string `json:"status,omitempty"`
	Description string `json:"description,omitempty"`
	Class       string `json:"class,omitempty"`
}

// Activity represents a activity entry in an AndroidManifest.xml file
// for our report
type Activity struct {
	SastID string `json:"sast,omitempty"`
	Name   string `json:"activity,omitempty"`
}

// Service represents a service entry in an AndroidManifest.xml file
// for our report
type Service struct {
	SastID string `json:"sast,omitempty"`
	Name   string `json:"service,omitempty"`
}

// BroadcastReceiver represents a broadcast receiver entry in an AndroidManifest.xml file
// for our report
type BroadcastReceiver struct {
	SastID string `json:"sast,omitempty"`
	Name   string `json:"receiver,omitempty"`
}

// ManifestPermission represents a permission entry in an AndroidManifest.xml file
// for our report

type ManifestPermission struct {
	Title             string `json:"title,omitempty"`
	Status            string `json:"status,omitempty"`
	Description       string `json:"description,omitempty"`
	Description_pt_br string `json:"description_PT-BR,omitempty"`
	Description_en    string `json:"description_EN,omitempty"`
	Description_es    string `json:"description_ES,omitempty"`

	Info       string `json:"info,omitempty"`
	Info_pt_br string `json:"info_PT-BR,omitempty"`
	Info_en    string `json:"info_EN,omitempty"`
	Info_es    string `json:"info_ES,omitempty"`

	SastID string `json:"sast,omitempty"`
}

// AndroidReport represents the specific data structure about
// all the Android related source code
type AndroidReport struct {
	DRA                     []DRA                `json:"dra"`
	AndroidInfo             AndroidInfo          `json:"android,omitempty"`
	Services                []Service            `json:"services,omitempty"`
	ManifestVulnerabilities []ManifestEntry      `json:"manifest,omitempty"`
	BroadcastReceivers      []BroadcastReceiver  `json:"receivers,omitempty"`
	Libraries               []Library            `json:"libraries,omitempty"`
	AvailableActivities     []Activity           `json:"activities,omitempty"`
	ManifestPermissions     []ManifestPermission `json:"permissions,omitempty"`
	Vulnerabilities         []Vulnerability      `json:"vulnerabilities,omitempty"`
	BrowsableActivities     []BrowsableActivity  `json:"browsableActivities,omitempty"`
}

// SetSastID sets the SastID for the given report
func (report *AndroidReport) SetSastID(sastID string) {
	report.AndroidInfo.SastID = sastID
}

// AddDRAEmails includes the extracted emails in the report internal list
func (report *AndroidReport) AddDRAEmails(emails []string, filepath string) {
	draEmails := addReportDRADataByType(draEmailType, report.AndroidInfo.SastID, filepath, emails)

	report.DRA = append(report.DRA, draEmails...)
}

// AddDRAURLs includes the extracted URLs in the report internal list
func (report *AndroidReport) AddDRAURLs(urls []string, filepath string) {
	draURLs := addReportDRADataByType(draURLType, report.AndroidInfo.SastID, filepath, urls)

	report.DRA = append(report.DRA, draURLs...)
}

// GetDRAEmails returns the list of already found emails in data extraction
func (report *AndroidReport) GetDRAEmails() []string {
	return getReportDRADataByType(report.DRA, draEmailType)
}

// GetDRAURLs returns the list of already found URLs in data extraction
func (report *AndroidReport) GetDRAURLs() []string {
	return getReportDRADataByType(report.DRA, draURLType)
}
