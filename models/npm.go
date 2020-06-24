package models

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
