package analyzers

// Info holds data about the current rule been evaluated
type Info struct {
	Description   string  `json:"description"`
	CWE           string  `json:"cwe"`
	CVSS          float64 `json:"cvss"`
	Severity      string  `json:"severity"`
	Title         string  `json:"title"`
	Recomendation string  `json:"recomendation"`
}

// Finding represents a issue found in the source code
type Finding struct {
	// Unique identifier
	VulnerabilityID string `json:"vuln_id,omitempty"`
	// General info
	Line      int    `json:"line"`
	Info      Info   `json:"rule"`
	Column    int    `json:"column"`
	Sample    string `json:"sample"`
	ScopeName string `json:"scopeName"`
}

// FileSummary holds all the issues found in the given file, and the file name.
type FileSummary struct {
	Name     string    `json:"name"`
	Findings []Finding `json:"findings"`
}
