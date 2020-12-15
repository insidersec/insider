package insider

import (
	"context"
	"encoding/xml"
	"errors"
	"log"
	"os"
	"regexp"

	"github.com/insidersec/insider/engine"
	"github.com/insidersec/insider/report"
)

const (
	// UnknownStatus is the default status for a Manifest permission
	UnknownStatus string = "Desconhecido"
)

var (
	manifestFilter = regexp.MustCompile(`AndroidManifest\.xml`)
	gradleFilter   = regexp.MustCompile(`dependencies\w*\.gradle`)

	launcherActivity = regexp.MustCompile(`android.intent.category.LAUNCHER`)
	mainActivity     = regexp.MustCompile(`android.intent.action.MAIN`)

	extractGradleVersionName       = regexp.MustCompile(`versionName\s+(?:=|)(\d*\.\d*\.\d*)`)
	extractGradleVersionNumber     = regexp.MustCompile(`versionNumber\s+(?:\=\s|)(?:(?:(?:['"]|)(.*)(?:['"]|))|\d*)`)
	extractGradleMinimumSDKVersion = regexp.MustCompile(`minSdkVersion\s+(?:\=\s|)(?:(?:(?:['"]|)(.*)(?:['"]|))|\d*)`)
	extractGradleTargetSDKVersion  = regexp.MustCompile(`targetSdkVersion\s+(?:\=\s|)(?:(?:(?:['"]|)(.*)(?:['"]|))|\d*)`)
	extractGradleMaximumSDKVersion = regexp.MustCompile(`maxSdkVersion\s+(?:\=\s|)(?:(?:(?:['"]|)(.*)(?:['"]|))|\d*)`)
)

type AndroidAnalyzer struct {
	logger *log.Logger
}

func NewAndroidAnalyzer(logger *log.Logger) AndroidAnalyzer {
	return AndroidAnalyzer{
		logger: logger,
	}
}

func (a AndroidAnalyzer) Analyze(ctx context.Context, dir string) (report.Reporter, error) {
	var r report.AndroidReporter

	a.logger.Printf("Analysing AndroidManifest file at %s\n", dir)
	if err := a.analyzeManifest(ctx, &r, dir); err != nil {
		return report.AndroidReporter{}, err
	}

	return r, nil
}

func (a AndroidAnalyzer) analyzeManifest(ctx context.Context, r *report.AndroidReporter, dir string) error {
	manifestPermissionData := getManifestPermission()

	manifestFiles, err := engine.FindInputFiles(dir, false, findManifests)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			a.logger.Printf("AndroidManifest not found on %s\n", dir)
			return nil
		}
		return err
	}

	for _, file := range manifestFiles {
		var manifest Manifest

		if err := xml.Unmarshal([]byte(file.Content), &manifest); err != nil {
			return err
		}

		if isMainPackage(file.Content) {
			a.fillMainManifest(manifest, r)
		} else {
			r.AndroidInfo.SubPackageNames = append(r.AndroidInfo.SubPackageNames, manifest.PackageName)
		}

		for _, permission := range manifest.Permissions {
			a.fillManifestPermissions(manifestPermissionData, permission, r)
		}

		for _, manifestReceiver := range manifest.Application.BroadcastReceivers {
			receiver := report.BroadcastReceiver{
				Name: manifestReceiver.Name,
			}
			r.BroadcastReceivers = append(r.BroadcastReceivers, receiver)
		}

		for _, manifestService := range manifest.Application.Services {
			service := report.Service{
				Name: manifestService.Name,
			}
			r.Services = append(r.Services, service)
		}
	}

	// Fallback cenario for some information about the application when
	// the AndroidManifest.xml wasn't expanded by Gradle build scripts yet
	// a.k.a the source code being analyzed is not a artifact.
	if r.AndroidInfo.TargetSDK == "" && r.AndroidInfo.MinimumSDK == "" && r.AndroidInfo.MaximumSDK == "" {
		if err := a.fillAndroidInfoFromGradle(dir, r); err != nil {
			return err
		}
	}
	return nil
}

func (a AndroidAnalyzer) fillAndroidInfoFromGradle(dir string, r *report.AndroidReporter) error {
	files, err := engine.FindInputFiles(dir, false, findGradleFiles)
	if err != nil {
		return err
	}

	for _, file := range files {
		if extractGradleVersionNumber.MatchString(file.Content) {
			finding := extractGradleVersionNumber.FindStringSubmatch(file.Content)
			if finding != nil {
				r.AndroidInfo.AndroidVersionCode = finding[len(finding)-1]
			}
		}

		if extractGradleVersionName.MatchString(file.Content) {
			finding := extractGradleVersionName.FindStringSubmatch(file.Content)
			if finding != nil {
				r.AndroidInfo.AndroidVersionName = finding[len(finding)-1]
			}
		}

		if extractGradleTargetSDKVersion.MatchString(file.Content) {
			finding := extractGradleTargetSDKVersion.FindStringSubmatch(file.Content)
			if finding != nil {
				r.AndroidInfo.TargetSDK = finding[len(finding)-1]
			}
		}

		if extractGradleMinimumSDKVersion.MatchString(file.Content) {
			finding := extractGradleMinimumSDKVersion.FindStringSubmatch(file.Content)
			if finding != nil {
				r.AndroidInfo.MinimumSDK = finding[len(finding)-1]
			}
		}

		if extractGradleMaximumSDKVersion.MatchString(file.Content) {
			finding := extractGradleMaximumSDKVersion.FindStringSubmatch(file.Content)
			if finding != nil {
				r.AndroidInfo.MaximumSDK = finding[len(finding)-1]
			}
		}
	}
	return nil
}

func (a AndroidAnalyzer) fillManifestPermissions(data []report.ManifestPermission, permission Permission, r *report.AndroidReporter) {
	manifestPermission := report.ManifestPermission{}
	manifestPermission.Title = permission.Name

	for _, perm := range data {
		if perm.Title == permission.Name {
			manifestPermission.Status = perm.Status
			manifestPermission.Description = perm.Description
			manifestPermission.Info = perm.Info
		} else {
			manifestPermission.Status = UnknownStatus
		}
	}
	r.ManifestPermissions = append(r.ManifestPermissions, manifestPermission)
}

func (a AndroidAnalyzer) fillMainManifest(manifest Manifest, r *report.AndroidReporter) {
	for _, activity := range manifest.Application.Activities {
		for _, intentFilter := range activity.IntentFilter.Actions {
			if mainActivity.MatchString(intentFilter.Name) {
				r.AndroidInfo.MainActivity = activity.Name
			}
		}

		a := report.Activity{
			Name: activity.Name,
		}

		r.AvailableActivities = append(r.AvailableActivities, a)
	}

	r.AndroidInfo.PackageName = manifest.PackageName
	r.AndroidInfo.TargetSDK = manifest.SDKInfo.TargetSDKVersion
	r.AndroidInfo.MinimumSDK = manifest.SDKInfo.MinimumSDKVersion
	r.AndroidInfo.MaximumSDK = manifest.SDKInfo.MaximumSDKVersion
	r.AndroidInfo.AndroidVersionName = manifest.VersionName
	r.AndroidInfo.AndroidVersionCode = manifest.VersionCode

	if r.AndroidInfo.TargetSDK == "" {
		r.AndroidInfo.TargetSDK = manifest.SDKInfo.MinimumSDKVersion
	}
}

func isMainPackage(content string) bool {
	return mainActivity.MatchString(content) && launcherActivity.MatchString(content)
}

func findGradleFiles(filename string) bool {
	return gradleFilter.MatchString(filename)
}

func findManifests(filename string) bool {
	return manifestFilter.MatchString(filename)
}

// Permission is a AndroidManifest permission entry
type Permission struct {
	Name string `xml:"name,attr"`
}

// SDKInfo is the AndroidManifest informative entry
type SDKInfo struct {
	MinimumSDKVersion string `xml:"minSdkVersion,attr"`
	TargetSDKVersion  string `xml:"targetSdkVersion,attr"`
	MaximumSDKVersion string `xml:"maxSdkVersion,attr"`
}

// IntentAction represents a Action for the Android Activity.
type IntentAction struct {
	Name string `xml:"name,attr"`
}

// IntentCategory holds data about the Activity category.
type IntentCategory struct {
	Name string `xml:"name,attr"`
}

// IntentFilter holds metadata about the `intention-filter` tag for the given Activity.
type IntentFilter struct {
	Actions    []IntentAction `xml:"action"`
	Categories IntentCategory `xml:"category"`
}

// ManifestActivity holds data from the `activities` tag in the AndroidManifest.xml file
type ManifestActivity struct {
	Name         string       `xml:"name,attr"`
	IntentFilter IntentFilter `xml:"intent-filter"`
}

// BroadcastReceiver holds data about a broadcast receiver entry in AndroidManifest.xml
type BroadcastReceiver struct {
	Name string `xml:"name,attr"`
}

// Service holds data about a Android Service entry in AndroidManifest.xml file
type Service struct {
	Name string `xml:"name,attr"`
}

// ApplicationInfo holds app data from AndroidManifest.xml
type ApplicationInfo struct {
	Activities         []ManifestActivity  `xml:"activity"`
	BroadcastReceivers []BroadcastReceiver `xml:"receiver"`
	Services           []Service           `xml:"service"`
}

// Manifest holds all the data about the AndroidManifest file
type Manifest struct {
	PackageName string          `xml:"package,attr"`
	Permissions []Permission    `xml:"uses-permission"`
	SDKInfo     SDKInfo         `xml:"uses-sdk"`
	Application ApplicationInfo `xml:"application"`

	VersionName string `xml:"versionName,attr"`
	VersionCode string `xml:"versionCode,attr"`
}
