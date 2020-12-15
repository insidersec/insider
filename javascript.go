package insider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/insidersec/insider/report"
)

type JavaScriptAnalyzer struct {
	logger *log.Logger
	npm    NPM
}

func NewJavaScriptAnalyzer(npm NPM, logger *log.Logger) JavaScriptAnalyzer {
	return JavaScriptAnalyzer{
		logger: logger,
		npm:    npm,
	}
}

func (js JavaScriptAnalyzer) Analyze(ctx context.Context, dir string) (report.Reporter, error) {
	var r report.Report
	js.logger.Println("Analysing JavaScript dependencies")
	if err := js.analyzeDependencies(ctx, &r, dir); err != nil {
		return report.Report{}, err
	}
	return r, nil
}

func (js JavaScriptAnalyzer) analyzeDependencies(ctx context.Context, r *report.Report, dir string) error {
	pkgJSON, err := js.findPackageJSON(dir)
	if err != nil {
		if !os.IsNotExist(err) {
			return err
		}
		js.logger.Printf("Not found package.json at %s\n", dir)
		return nil
	}

	libraries := make([]report.Library, 0, len(pkgJSON.Dependencies))

	for dependency, version := range pkgJSON.Dependencies {
		libraryFound := report.Library{
			Version: version,
			Name:    dependency,
		}
		libraries = append(libraries, libraryFound)
	}

	r.Libraries = libraries

	r.Info.Name = pkgJSON.Name
	r.Info.Version = pkgJSON.Version

	auditResult, err := js.npm.AuditLibraries(pkgJSON)
	if err != nil {
		return err
	}

	for _, libraryAdvisory := range auditResult.Advisories {
		libraryIssue := convertAdvisoryToReport(libraryAdvisory)

		r.LibraryIssues = append(r.LibraryIssues, libraryIssue)
	}

	return nil
}

func (js JavaScriptAnalyzer) findPackageJSON(dir string) (PackageJSON, error) {
	file := filepath.Join(dir, "package.json")
	b, err := ioutil.ReadFile(file)
	if err != nil {
		return PackageJSON{}, err
	}
	var pkg PackageJSON
	if err := json.Unmarshal(b, &pkg); err != nil {
		return PackageJSON{}, err
	}
	return pkg, nil

}

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

type NPM interface {
	AuditLibraries(PackageJSON) (AuditResult, error)
}

// NPMDependency is a DTO for dependencies sent over to NPM's API
type NPMDependency struct {
	Version string `json:"version"`
}

// NPMAdvisoryPayload holds a DTO for sending Library information to the
// NPM Advisory API
type NPMAdvisoryPayload struct {
	Name              string                   `json:"name"`
	Version           string                   `json:"version"`
	RequiredLibraries map[string]string        `json:"requires"`
	Dependencies      map[string]NPMDependency `json:"dependencies"`
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

type AuditResult struct {
	Advisories map[string]Advisory `json:"advisories"`
}

type NpmAdvisory struct {
	url       string
	userAgent string
	client    *http.Client
}

func NewNPMAdvisory(url, userAgent string, timeout time.Duration) NpmAdvisory {
	return NpmAdvisory{
		url:       url,
		userAgent: userAgent,
		client: &http.Client{
			Timeout: timeout,
		},
	}
}

// AuditLibraries gets the information from NPM Advisory API for the given pkgJSON
func (npm NpmAdvisory) AuditLibraries(pkgJSON PackageJSON) (AuditResult, error) {
	body := transformLibrariesForAuditing(pkgJSON.Name, pkgJSON.Version, pkgJSON.Dependencies)

	bodyData, err := json.Marshal(body)
	if err != nil {
		return AuditResult{}, err
	}

	bodyReader := bytes.NewReader(bodyData)

	req, err := http.NewRequest(http.MethodPost, npm.url, bodyReader)
	if err != nil {
		return AuditResult{}, err
	}

	req.Header.Add("User-Agent", npm.userAgent)

	res, err := npm.client.Do(req)
	if err != nil {
		return AuditResult{}, err
	}
	defer res.Body.Close()

	responseData, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return AuditResult{}, err
	}

	var result AuditResult
	if err := json.Unmarshal(responseData, &result); err != nil {
		return AuditResult{}, err
	}

	return result, nil
}

// convertAdvisoryToReport do the trick to add the Advisory response from the NPM API
// to the standard reports.LibraryVulnerability struct
func convertAdvisoryToReport(advisory Advisory) report.LibraryVulnerability {
	var title string
	if advisory.Title == "" {
		title = fmt.Sprintf("Vulnerability - %s", advisory.ModuleName)
	} else {
		title = fmt.Sprintf("%s - %s", advisory.Title, advisory.ModuleName)
	}

	return report.LibraryVulnerability{
		Title:         title,
		ID:            advisory.ID,
		CWE:           advisory.CWE,
		CVEs:          strings.Join(advisory.CVEs, " "),
		Severity:      advisory.Severity,
		Description:   advisory.Overview,
		Recomendation: advisory.Recomendation,
	}
}

func transformLibrariesForAuditing(name, version string, libraries map[string]string) (payload NPMAdvisoryPayload) {
	payload.Name = name
	payload.Version = version
	payload.RequiredLibraries = libraries

	payload.Dependencies = make(map[string]NPMDependency)

	for module, moduleVersion := range libraries {
		dependency := NPMDependency{
			Version: moduleVersion,
		}

		payload.Dependencies[module] = dependency
	}

	return payload
}
