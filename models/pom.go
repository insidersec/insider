package models

// POM or the Project Object Model is the fundamental unit
// on a Maven based project.
type POM struct {
	Name          string            `xml:"name"`
	Version       string            `xml:"version"`
	GroupID       string            `xml:"groupId"`
	PackagingMode string            `xml:"packaging"`
	ArtifactID    string            `xml:"artifactId"`
	Description   string            `xml:"description"`
	Dependencies  []POMDependencies `xml:"dependencies>dependency"`
}

// POMDependencies holds data about external objects of
// a POM project
type POMDependencies struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
}
