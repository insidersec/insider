package models

// PackageJSON holds data about the package.json file
// on JavaScript projects
type PackageJSON struct {
	// General information
	Name      string `json:"name"`
	Version   string `json:"version"`
	IsPrivate bool   `json:"private"`
	License   string `json:"license"`

	// Metadata about the root package
	SupportedOSs              []string          `json:"os"`
	SupportedCPUArchitectures []string          `json:"cpu"`
	SupportedEngines          map[string]string `json:"engines"`
	Keywords                  []string          `json:"keywords"`

	// Main information that we are looking for :D
	Dependencies map[string]string `json:"dependencies"`
}

// AdvisoryMetadata self-explained
type AdvisoryMetadata struct {
	ModuleType     string `json:"module_type"`
	Exploitability int    `json:"exploitability"`
}

// Advisory holds data about the advisories section
type Advisory struct {
	ID       int              `json:"id"`
	Metadata AdvisoryMetadata `json:"metadata"`

	// Module info
	ModuleName         string `json:"module_name"`
	PatchedVersions    string `json:"patched_versions"`
	VulnerableVersions string `json:"vulnerable_versions"`

	// Vulnerability info
	ReferenceURL  string   `json:"url"`
	CVEs          []string `json:"cves"`
	CWE           string   `json:"cwe"`
	Title         string   `json:"title"`
	Severity      string   `json:"severity"`
	Overview      string   `json:"overview"`
	References    string   `json:"references"`
	Recomendation string   `json:"recommendation"`
}

// AuditResult holds the data for the NPM Advisory API
type AuditResult struct {
	Advisories map[string]Advisory `json:"advisories"`
}
