package analyzers

import (
	"encoding/xml"
	"fmt"
	"regexp"
	"strconv"
	"github.com/insidersec/insider/models"
	"github.com/insidersec/insider/visitor"
)

var xmlFilesFilter *regexp.Regexp
var haveMainActivity *regexp.Regexp
var gradleFilesFilter *regexp.Regexp

var extractGradleVersionName *regexp.Regexp
var extractGradleVersionNumber *regexp.Regexp
var extractGradleTargetSDKVersion *regexp.Regexp
var extractGradleMinimumSDKVersion *regexp.Regexp
var extractGradleMaximumSDKVersion *regexp.Regexp

const (
	// UnknownStatus is the default status for a Manifest permission
	UnknownStatus string = "Desconhecido"
)

// Permission is a AndroidManifest permission entry
type Permission struct {
	Name     string `xml:"name,attr"`
	Required bool   `xml:"required,attr"`
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

// ApplicationInfo holds app data from AndroidManifest.xml
type ApplicationInfo struct {
	Name           string             `xml:"name,attr"`
	AllowADBBackup bool               `xml:"allowBackup,attr"`
	Activities     []ManifestActivity `xml:"activity"`
}

// Manifest holds all the data about the AndroidManifest file
type Manifest struct {
	PackageName string          `xml:"package,attr"`
	Permissions []Permission    `xml:"uses-permission"`
	SDKInfo     SDKInfo         `xml:"uses-sdk"`
	Application ApplicationInfo `xml:"application"`

	// Info section
	VersionName            string `xml:"versionName,attr"`
	VersionCode            string `xml:"versionCode,attr"`
	CompiledSDKVersion     string `xml:"compileSdkVersion,attr"`
	CompiledSDKVersionCode string `xml:"compileSdkVersionCodename,attr"`
}

func init() {
	xmlFilesFilter = regexp.MustCompile(`AndroidManifest\.xml`)
	gradleFilesFilter = regexp.MustCompile(`dependencies\w*\.gradle`)

	haveMainActivity = regexp.MustCompile(`android.intent.action.MAIN`)

	extractGradleVersionName = regexp.MustCompile(`versionName\s+(?:=|)(\d*\.\d*\.\d*)`)
	extractGradleVersionNumber = regexp.MustCompile(`versionNumber\s+(?:\=\s|)(?:(?:(?:['"]|)(.*)(?:['"]|))|\d*)`)
	extractGradleMinimumSDKVersion = regexp.MustCompile(`minSdkVersion\s+(?:\=\s|)(?:(?:(?:['"]|)(.*)(?:['"]|))|\d*)`)
	extractGradleTargetSDKVersion = regexp.MustCompile(`targetSdkVersion\s+(?:\=\s|)(?:(?:(?:['"]|)(.*)(?:['"]|))|\d*)`)
	extractGradleMaximumSDKVersion = regexp.MustCompile(`maxSdkVersion\s+(?:\=\s|)(?:(?:(?:['"]|)(.*)(?:['"]|))|\d*)`)

}

func isMainPackage(content string) bool {
	haveLauncherActivity := regexp.MustCompile(`android.intent.category.LAUNCHER`)

	return haveMainActivity.MatchString(content) && haveLauncherActivity.MatchString(content)
}

func findGradleFiles(filename string) bool {
	return gradleFilesFilter.MatchString(filename)
}

func findManifests(filename string) bool {
	return xmlFilesFilter.MatchString(filename)
}

// AnalyzeAndroidManifest analyzes the given directory and builds the
// AndroidInfo field of the AndroidReport struct, only modifying this field inside the pointer.
func AnalyzeAndroidManifest(dirname string, report *models.AndroidReport) error {
	manifestPermissionData := loadManifestData()

	appSize, err := GetUnpackedAppSize(dirname)

	if err != nil {
		return err
	}

	report.AndroidInfo.Size = fmt.Sprintf("%s MB", strconv.Itoa(appSize))

	manifestFiles, err := visitor.FindFiles(dirname, false, findManifests)

	if err != nil {
		return err
	}

	for _, file := range manifestFiles {
		manifest := Manifest{}

		err = xml.Unmarshal([]byte(file.Content), &manifest)

		if err != nil {
			return err
		}

		if isMainPackage(file.Content) {
			for _, activity := range manifest.Application.Activities {
				for _, intentFilter := range activity.IntentFilter.Actions {
					if haveMainActivity.MatchString(intentFilter.Name) {
						report.AndroidInfo.MainActivity = activity.Name
					}
				}

				reportActivity := models.Activity{
					Name: activity.Name,
				}

				report.AvailableActivities = append(report.AvailableActivities, reportActivity)
			}

			report.AndroidInfo.PackageName = manifest.PackageName

			report.AndroidInfo.TargetSDK = manifest.SDKInfo.TargetSDKVersion
			report.AndroidInfo.MinimumSDK = manifest.SDKInfo.MinimumSDKVersion
			report.AndroidInfo.MaximumSDK = manifest.SDKInfo.MaximumSDKVersion

			if report.AndroidInfo.TargetSDK == "" {
				report.AndroidInfo.TargetSDK = manifest.SDKInfo.MinimumSDKVersion
			}

			report.AndroidInfo.AndroidVersionName = manifest.VersionName
			report.AndroidInfo.AndroidVersionCode = manifest.VersionCode
		} else {
			report.AndroidInfo.SubPackageNames = append(report.AndroidInfo.SubPackageNames, manifest.PackageName)
		}

		if len(manifest.Permissions) >= 0 {
			// For each permission found in the AndroidManifest.xml file
			for _, permission := range manifest.Permissions {
				manifestPermission := models.ManifestPermission{}
				manifestPermission.Title = permission.Name
				// Searches in our stored manifest data for the whole data about that permission.
				// I know it's a dumb algorithm, but for now, we only have 198 permission entries
				// so the complexity isn't that big. :v
				// but this can still be a performance bottleneck :/
				for _, permissionDescription := range manifestPermissionData {
					if permissionDescription.Title == permission.Name {
						manifestPermission.Status = permissionDescription.Status
						manifestPermission.Description = permissionDescription.Description
						manifestPermission.Info = permissionDescription.Info
					} else {
						manifestPermission.Status = UnknownStatus
					}
				}
				report.ManifestPermissions = append(report.ManifestPermissions, manifestPermission)
			}
		}
	}

	gradleFiles, err := visitor.FindFiles(dirname, false, findGradleFiles)

	if err != nil {
		return err
	}

	for _, buildFile := range gradleFiles {
		if extractGradleVersionNumber.MatchString(buildFile.Content) {
			finding := extractGradleVersionNumber.FindStringSubmatch(buildFile.Content)
			if finding != nil {
				report.AndroidInfo.AndroidVersionCode = finding[len(finding)-1]
			}
		}

		if extractGradleVersionName.MatchString(buildFile.Content) {
			finding := extractGradleVersionName.FindStringSubmatch(buildFile.Content)
			if finding != nil {
				report.AndroidInfo.AndroidVersionName = finding[len(finding)-1]
			}
		}

		if extractGradleTargetSDKVersion.MatchString(buildFile.Content) {
			finding := extractGradleTargetSDKVersion.FindStringSubmatch(buildFile.Content)
			if finding != nil {
				report.AndroidInfo.TargetSDK = finding[len(finding)-1]
			}
		}

		if extractGradleMinimumSDKVersion.MatchString(buildFile.Content) {
			finding := extractGradleMinimumSDKVersion.FindStringSubmatch(buildFile.Content)
			if finding != nil {
				report.AndroidInfo.MinimumSDK = finding[len(finding)-1]
			}
		}

		if extractGradleMaximumSDKVersion.MatchString(buildFile.Content) {
			finding := extractGradleMaximumSDKVersion.FindStringSubmatch(buildFile.Content)
			if finding != nil {
				report.AndroidInfo.MaximumSDK = finding[len(finding)-1]
			}
		}
	}

	return nil
}
