package report

import (
	"io"
)

type Result interface {
	ToReporter(dir string, base Reporter) (Reporter, error)
}

type Reporter interface {
	Json(out io.Writer) error
	Html(out io.Writer) error
	Resume(out io.Writer)
	Console(out io.Writer)
	SecurityScore() float64
}

// LibraryVulnerability is a structure to hold data
// about vulnerabilities found on libraries
// to Insider`s Console
type LibraryVulnerability struct {
	CWE           string `json:"cwe"`
	CVEs          string `json:"cves"`
	Title         string `json:"title"`
	Severity      string `json:"severity"`
	ID            int    `json:"advisoryId"`
	Description   string `json:"description"`
	Recomendation string `json:"recomendation"`
}

// Vulnerability is the default structure to represent a potentially
// dangerous piece code inside the source analyzed.
type Vulnerability struct {
	CVSS            float64 `json:"cvss"`
	CWE             string  `json:"cwe,omitempty"`
	Severity        string  `json:"severity,omitempty"`
	Line            int     `json:"line,omitempty"`
	Class           string  `json:"class,omitempty"`
	VulnerabilityID string  `json:"vul_id,omitempty"`
	Method          string  `json:"method,omitempty"`
	Column          int     `json:"column,omitempty"`
	Category        string  `json:"category,omitempty"`
	Priority        string  `json:"priority,omitempty"`
	Description     string  `json:"description,omitempty"`
	ClassMessage    string  `json:"classMessage,omitempty"`
	Recomendation   string  `json:"recomendation,omitempty"`
	MethodMessage   string  `json:"methodMessage,omitempty"`
}

// Library is the default representation of a library found inside
// analized source.
type Library struct {
	Name                 string `json:"name,omitempty"`
	Version              string `json:"current,omitempty"`
	Source               string `json:"source,omitempty"`
	CompatibilityVersion string `json:"compatiblityVersion,omitempty"`
}

// SASTInfo holds generic information about the overall report
type SASTInfo struct {
	Name          string  `json:"name,omitempty"`
	Version       string  `json:"version,omitempty"`
	AverageCVSS   float64 `json:"averageCvss,omitempty"`
	SecurityScore float64 `json:"securityScore,omitempty"`
	MD5           string  `json:"md5,omitempty"`
	Size          string  `json:"size,omitempty"`
	SHA1          string  `json:"sha1,omitempty"`
	SHA256        string  `json:"sha256,omitempty"`
	NumberOfLines int     `json:"numberOfLines,omitempty"`
}

// Base base report fields to all types of reports
type Base struct {
	Libraries       []Library       `json:"libraries,omitempty"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities,omitempty"`
	None            int             `json:"none"`
	Low             int             `json:"low"`
	Medium          int             `json:"medium"`
	High            int             `json:"high"`
	Critical        int             `json:"critical"`
	Total           int             `json:"total"`
}

// Report default report to all technologies excluding Ios and Android
type Report struct {
	Base
	LibraryIssues []LibraryVulnerability `json:"sca,omitempty"`
	Info          SASTInfo               `json:"sast,omitempty"`
}

func (r Report) Json(out io.Writer) error {
	return reportJson(r, out)
}

func (r Report) Html(out io.Writer) error {
	return reportHTML(defaultTemplate(), r, out)
}

func (r Report) Resume(out io.Writer) {
	resumeReport(r.SecurityScore(), len(r.Vulnerabilities), r.None, r.Low, r.Medium, r.High, r.Critical, r.Total, out)
}

func (r Report) Console(out io.Writer) {
	consoleReport(r.SecurityScore(), r.Libraries, r.Vulnerabilities, out)
}

func (r Report) SecurityScore() float64 {
	return r.Info.SecurityScore
}
