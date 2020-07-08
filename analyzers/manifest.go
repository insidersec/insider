package analyzers

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	"insider/models"
	"insider/models/reports"
	"insider/visitor"
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

func loadManifestData(lang string) (permissions []reports.ManifestPermission, err error) {
	fullPath, _ := os.Getwd()
	log.Println("fullpath", fullPath)
	projectPrefix := ""

	manifestData, err := ioutil.ReadFile(filepath.Join(fullPath, projectPrefix, "analyzers/manifest.json"))

	if err != nil {
		return permissions, err
	}

	err = json.Unmarshal(manifestData, &permissions)

	if err != nil {
		return permissions, err
	}
	lang = strings.ToLower(lang)
	for i, v := range permissions {
		r := reflect.ValueOf(v)
		desc := reflect.Indirect(r).FieldByName("Description_" + lang)
		info := reflect.Indirect(r).FieldByName("Info_" + lang)
		permissions[i].Description = desc.String()
		permissions[i].Info = info.String()
	}

	return permissions, nil
}

// AnalyzeAndroidManifest analyzes the given directory and builds the
// AndroidInfo field of the AndroidReport struct, only modifying this field inside the pointer.
// The sastID parameter is responsible only for later reference to this specific run.
// OBS.: You don't have to worry about this field, the Insider BFF will provide it.
func AnalyzeAndroidManifest(dirname, sastID string, report *reports.AndroidReport, lang string) error {

	//manifestPermissionData, err := loadManifestData(lang)
	log.Println("Loading manifest permission")
	manifestPermissionData := GetManifestPermission()
	log.Println(len(manifestPermissionData))

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
		manifest := models.Manifest{}

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

				reportActivity := reports.Activity{
					SastID: sastID,
					Name:   activity.Name,
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
				manifestPermission := reports.ManifestPermission{}
				manifestPermission.SastID = sastID
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

		if len(manifest.Application.BroadcastReceivers) >= 0 {
			for _, manifestReceiver := range manifest.Application.BroadcastReceivers {
				receiver := reports.BroadcastReceiver{
					SastID: sastID,
					Name:   manifestReceiver.Name,
				}

				report.BroadcastReceivers = append(report.BroadcastReceivers, receiver)
			}
		}

		if len(manifest.Application.Services) >= 0 {
			for _, manifestService := range manifest.Application.Services {
				service := reports.Service{
					SastID: sastID,
					Name:   manifestService.Name,
				}

				report.Services = append(report.Services, service)
			}
		}
	}

	// Fallback cenario for some information about the application when
	// the AndroidManifest.xml wasn't expanded by Gradle build scripts yet
	// a.k.a the source code being analyzed is not a artifact.
	if report.AndroidInfo.TargetSDK == "" &&
		report.AndroidInfo.MinimumSDK == "" &&
		report.AndroidInfo.MaximumSDK == "" {
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
	}

	return nil
}
