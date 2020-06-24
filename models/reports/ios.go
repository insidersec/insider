package reports

// IOSInfo holds information about iOS apps
type IOSInfo struct {
	SastID             string  `json:"sast,omitempty"`
	BinaryID           string  `json:"binId,omitempty"`
	BinaryType         string  `json:"binType,omitempty"`
	AppName            string  `json:"binName,omitempty"`
	TargetVersion      string  `json:"sdk,omitempty"`
	MinimumOSVersion   string  `json:"min,omitempty"`
	SupportedPlatforms string  `json:"pltfm,omitempty"`
	Build              string  `json:"build,omitempty"`
	AverageCVSS        float64 `json:"averageCvss,omitempty"`
	SecurityScore      float32 `json:"securityScore,omitempty"`
	Size               string  `json:"size,omitempty"`
	MD5                string  `json:"md5,omitempty"`
	SHA1               string  `json:"sha1,omitempty"`
	SHA256             string  `json:"sha256,omitempty"`
	NumberOfLines      int     `json:"numberOfLines,omitempty"`
}

// IOSPermission holds iOS permissions data
type IOSPermission struct {
	SastID      string `json:"sast,omitempty"`
	Name        string `json:"permission,omitempty"`
	Reason      string `json:"reason,omitempty"`
	Description string `json:"description,omitempty"`
}

// IOSReport is the representation of the iOS report
type IOSReport struct {
	DRA             []DRA           `json:"dra"`
	IOSInfo         IOSInfo         `json:"ios,omitempty"`
	Libraries       []Library       `json:"libraries,omitempty"`
	Permissions     []IOSPermission `json:"permissions,omitempty"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities,omitempty"`
}

// SetSastID sets the SastID for the given report
func (report *IOSReport) SetSastID(sastID string) {
	report.IOSInfo.SastID = sastID
}

// AddDRAEmails includes the extracted emails in the report internal list
func (report *IOSReport) AddDRAEmails(emails []string, filepath string) {
	draEmails := addReportDRADataByType(draEmailType, report.IOSInfo.SastID, filepath, emails)

	report.DRA = append(report.DRA, draEmails...)
}

// AddDRAURLs includes the extracted URLs in the report internal list
func (report *IOSReport) AddDRAURLs(urls []string, filepath string) {
	draURLs := addReportDRADataByType(draURLType, report.IOSInfo.SastID, filepath, urls)

	report.DRA = append(report.DRA, draURLs...)
}

// GetDRAEmails returns the list of already found emails in data extraction
func (report *IOSReport) GetDRAEmails() []string {
	return getReportDRADataByType(report.DRA, draEmailType)
}

// GetDRAURLs returns the list of already found URLs in data extraction
func (report *IOSReport) GetDRAURLs() []string {
	return getReportDRADataByType(report.DRA, draURLType)
}
