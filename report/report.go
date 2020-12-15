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

// DRA stands for Digital Risks anaytics, a key part of analyzing
// the overall data exposure about the application
type DRA struct {
	Data     string `json:"dra"`
	Type     string `json:"type"`
	FilePath string `json:"file"`
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
	CVSS            float64  `json:"cvss"`
	CWE             string   `json:"cwe,omitempty"`
	Rank            string   `json:"rank,omitempty"`
	Line            int      `json:"line,omitempty"`
	Class           string   `json:"class,omitempty"`
	VulnerabilityID string   `json:"vul_id,omitempty"`
	Method          string   `json:"method,omitempty"`
	Column          int      `json:"column,omitempty"`
	Category        string   `json:"category,omitempty"`
	Priority        string   `json:"priority,omitempty"`
	LongMessage     string   `json:"longMessage,omitempty"`
	ClassMessage    string   `json:"classMessage,omitempty"`
	ShortMessage    string   `json:"shortMessage,omitempty"`
	MethodMessage   string   `json:"methodMessage,omitempty"`
	AffectedFiles   []string `json:"affectedFiles,omitempty"`
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

type Report struct {
	DRA             []DRA                  `json:"dra"`
	LibraryIssues   []LibraryVulnerability `json:"sca,omitempty"`
	Info            SASTInfo               `json:"sast,omitempty"`
	Libraries       []Library              `json:"libraries,omitempty"`
	Vulnerabilities []Vulnerability        `json:"vulnerabilities,omitempty"`
	High            int
	Medium          int
	Low             int
	Total           int
}

// CleanDRA cleans up the DRA list
func (report *Report) CleanDRA(dir string) error {
	report.DRA = unique(report.DRA)
	dra, err := cleanDRA(dir, report.DRA)
	if err != nil {
		return err
	}
	report.DRA = dra
	return nil
}

func (r Report) Json(out io.Writer) error {
	return reportJson(r, out)
}

func (r Report) Html(out io.Writer) error {
	return reportHTML(r, out)
}

func (r Report) Resume(out io.Writer) {
	resumeReport(r.SecurityScore(), len(r.DRA), len(r.Vulnerabilities), r.High, r.Medium, r.Low, r.Total, out)
}

func (r Report) Console(out io.Writer) {
	consoleReport(r.SecurityScore(), r.DRA, r.Libraries, r.Vulnerabilities, out)
}

func (r Report) SecurityScore() float64 {
	return r.Info.SecurityScore
}
