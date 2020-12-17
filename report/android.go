package report

import "io"

// AndroidInfo is all the metadata we collect from an AndroidManifest.xml file
// for our report
type AndroidInfo struct {
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
	AverageCVSS        float64  `json:"averageCvss,omitempty"`
	SecurityScore      float64  `json:"securityScore,omitempty"`
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
	SastID          string
	Title           string   `json:"title,omitempty"`
	Hosts           []string `json:"hosts,omitempty"`
	MIMETypes       []string `json:"mimeTypes,omitempty"`
	CallableSchemes []string `json:"schemes,omitempty"`
}

// ManifestEntry represents a permission entry in an AndroidManifest.xml file
// for our report
type ManifestEntry struct {
	Title       string `json:"title,omitempty"`
	Status      string `json:"status,omitempty"`
	Description string `json:"description,omitempty"`
	Class       string `json:"class,omitempty"`
}

// Activity represents a activity entry in an AndroidManifest.xml file
// for our report
type Activity struct {
	Name string `json:"activity,omitempty"`
}

// Service represents a service entry in an AndroidManifest.xml file
// for our report
type Service struct {
	Name string `json:"service,omitempty"`
}

// BroadcastReceiver represents a broadcast receiver entry in an AndroidManifest.xml file
// for our report
type BroadcastReceiver struct {
	Name string `json:"receiver,omitempty"`
}

// ManifestPermission represents a permission entry in an AndroidManifest.xml file
// for our report
type ManifestPermission struct {
	Title       string `json:"title,omitempty"`
	Status      string `json:"status,omitempty"`
	Description string `json:"description,omitempty"`
	Info        string `json:"info,omitempty"`
}

// AndroidReporter report of Android analysis
type AndroidReporter struct {
	Base
	AndroidInfo             AndroidInfo          `json:"android,omitempty"`
	Services                []Service            `json:"services,omitempty"`
	ManifestVulnerabilities []ManifestEntry      `json:"manifest,omitempty"`
	BroadcastReceivers      []BroadcastReceiver  `json:"receivers,omitempty"`
	AvailableActivities     []Activity           `json:"activities,omitempty"`
	ManifestPermissions     []ManifestPermission `json:"permissions,omitempty"`
	BrowsableActivities     []BrowsableActivity  `json:"browsableActivities,omitempty"`
}

// CleanDRA cleans up the DRA list
func (report *AndroidReporter) CleanDRA(dir string) error {
	report.DRA = unique(report.DRA)
	dra, err := cleanDRA(dir, report.DRA)
	if err != nil {
		return err
	}
	report.DRA = dra
	return nil
}

func (r AndroidReporter) Json(out io.Writer) error {
	return reportJson(r, out)
}

func (r AndroidReporter) Html(out io.Writer) error {
	return reportHTML(r, out)
}

func (r AndroidReporter) Resume(out io.Writer) {
	resumeReport(r.SecurityScore(), len(r.DRA), len(r.Vulnerabilities), r.High, r.Medium, r.Low, r.Total, out)
}

func (r AndroidReporter) Console(out io.Writer) {
	consoleReport(r.SecurityScore(), r.DRA, r.Libraries, r.Vulnerabilities, out)
}

func (r AndroidReporter) SecurityScore() float64 {
	return r.AndroidInfo.SecurityScore
}
