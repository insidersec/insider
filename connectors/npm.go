package connectors

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"

	"insider/models"
)

const (
	// NPMAdvisoryURL is the static route prefix for the NPM API
	NPMAdvisoryURL string = "https://registry.npmjs.org/-/npm/v1/security/audits"

	// Internals
	npmUserAgent string = "npm-registry-fetch@5.0.1/node@v12.5.0+x64 (linux)"
)

func transformLibrariesForAuditing(
	name, version string,
	libraries map[string]string) (payload models.NPMAdvisoryPayload) {
	payload.Name = name
	payload.Version = version
	payload.RequiredLibraries = libraries

	// Don't know why the hell I always need to put a empty map
	payload.Dependencies = make(map[string]models.NPMDependency)

	for module, moduleVersion := range libraries {
		dependency := models.NPMDependency{
			Version: moduleVersion,
		}

		payload.Dependencies[module] = dependency
	}

	return payload
}

// AuditLibraries gets the information from NPM Advisory API
// for the given package.json file :D
func AuditLibraries(packageData models.PackageJSON) (result models.AuditResult, err error) {
	client := NewHTTPClient()

	body := transformLibrariesForAuditing(
		packageData.Name,
		packageData.Version,
		packageData.Dependencies,
	)

	bodyData, err := json.Marshal(body)

	if err != nil {
		return
	}

	bodyReader := bytes.NewReader(bodyData)

	req, err := http.NewRequest("POST", NPMAdvisoryURL, bodyReader)

	if err != nil {
		return
	}

	req.Header.Add("User-Agent", npmUserAgent)

	res, err := client.Do(req)

	if err != nil {
		return
	}

	defer res.Body.Close()

	responseData, err := ioutil.ReadAll(res.Body)

	if err != nil {
		return
	}

	err = json.Unmarshal(responseData, &result)

	return
}
