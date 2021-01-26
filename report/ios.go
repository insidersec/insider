package report

import "io"

// IOSInfo holds information about iOS apps
type IOSInfo struct {
	BinaryID           string  `json:"binId,omitempty"`
	BinaryType         string  `json:"binType,omitempty"`
	AppName            string  `json:"binName,omitempty"`
	TargetVersion      string  `json:"sdk,omitempty"`
	MinimumOSVersion   string  `json:"min,omitempty"`
	SupportedPlatforms string  `json:"pltfm,omitempty"`
	Build              string  `json:"build,omitempty"`
	AverageCVSS        float64 `json:"averageCvss,omitempty"`
	SecurityScore      float64 `json:"securityScore,omitempty"`
	Size               string  `json:"size,omitempty"`
	MD5                string  `json:"md5,omitempty"`
	SHA1               string  `json:"sha1,omitempty"`
	SHA256             string  `json:"sha256,omitempty"`
	NumberOfLines      int     `json:"numberOfLines,omitempty"`
}

// IOSPermission holds iOS permissions data
type IOSPermission struct {
	Name        string `json:"permission,omitempty"`
	Reason      string `json:"reason,omitempty"`
	Description string `json:"description,omitempty"`
}

// IOSReporter report of Ios analysis
type IOSReporter struct {
	Base
	IOSInfo     IOSInfo         `json:"ios,omitempty"`
	Permissions []IOSPermission `json:"permissions,omitempty"`
}

func (r IOSReporter) Json(out io.Writer) error {
	return reportJson(r, out)
}

func (r IOSReporter) Html(out io.Writer) error {
	return reportHTML(iosTemplate(), r, out)
}

func (r IOSReporter) Resume(out io.Writer) {
	resumeReport(r.SecurityScore(), len(r.Vulnerabilities), r.None, r.Low, r.Medium, r.High, r.Critical, r.Total, out)
}

func (r IOSReporter) Console(out io.Writer) {
	consoleReport(r.SecurityScore(), r.Libraries, r.Vulnerabilities, out)
}

func (r IOSReporter) SecurityScore() float64 {
	return r.IOSInfo.SecurityScore
}
