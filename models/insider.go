package models

// Vulnerability is the default structure to represent a potentially
// dangerous piece code inside the source analyzed.
type Vulnerability struct {
	OWASPReferenceID string `json:"owaspID"`
	CWE              string `json:"cwe,omitempty"`
	Severity         string `json:"severity,omitempty"`
	Recomendation    string `json:"recomendation,omitempty"`
	LongMessage      string `json:"longMessage,omitempty"`
	Class            string `json:"class,omitempty"`
	FileName         string `json:"filename,omitempty"`
	Method           string `json:"method,omitempty"`
	MethodMessage    string `json:"methodMessage,omitempty"`
	Line             int    `json:"line,omitempty"`
	Column           int    `json:"column,omitempty"`
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
	Size          string `json:"size,omitempty"`
	NumberOfLines int    `json:"numberOfLines,omitempty"`
}

// Report is a generic structure for any type of
// report generated
type Report struct {
	Info            SASTInfo        `json:"information,omitempty"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities,omitempty"`
	Libraries       []Library       `json:"libraries,omitempty"`
}
