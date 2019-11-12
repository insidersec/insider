package models

// Info holds data about the current rule been evaluated
type Info struct {
	CWE              string `json:"cwe"`
	Title            string `json:"title"`
	OWASPReferenceID string `json:"owaspID"`
	Severity         string `json:"severity"`
	Description      string `json:"description"`
	Recomendation    string `json:"recomendation"`
}

// Finding represents a issue found in the source code
type Finding struct {
	Line   int    `json:"line"`
	Info   Info   `json:"rule"`
	Column int    `json:"column"`
	Sample string `json:"sample"`
}

// FileSummary holds all the issues found in the given file, and the file name.
type FileSummary struct {
	Name     string    `json:"name"`
	Findings []Finding `json:"findings"`
}
