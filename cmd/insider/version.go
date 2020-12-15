package main

var (
	// Version is the build version
	Version string

	// GitCommit is the commit of the build
	GitCommit string

	// BuildDate is the date when the build was created
	BuildDate string
)

func prepareVersionInfo() {
	if Version == "" {
		Version = "dev"
	}
}
