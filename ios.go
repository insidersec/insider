package insider

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"

	"github.com/insidersec/insider/engine"
	"github.com/insidersec/insider/report"
)

var (
	extractLibraryFromPodfile  = regexp.MustCompile(`pod\s'(?P<name>[[:alnum:]]+)'(?:,\s'(?:~>|>=|<=|)(?P<version>\d\.\d\.\d|\s\d\.\d\.\d|\s\d\.\d)|)`)
	extractBundleID            = regexp.MustCompile(`<key>BUNDLE_ID</key>(?:\n*.*)<string>(.*)</string>`)
	plistFilesFilter           = regexp.MustCompile(`.plist`)
	informativeFilesFilter     = regexp.MustCompile(`.xcodeproj|.plist`)
	extractLibraryFromCartfile = regexp.MustCompile(`(git|github|binary)\s['"](?P<name>[a-zA-Z0-9\/\:\.\-]*)['"]\s(?:(?:~>\s|==\s|>=\s|<=\s|")(?P<version>\d+\.\d+\.\d+|\d+\.\d+)|\"(?P<branch>[a-zA-Z]+)\"|)`)
	cartfileFilter             = regexp.MustCompile(`(?i)cartfile`)
	cartfileResolverFilter     = regexp.MustCompile(`Cartfile.resolved`)
	podfileFilter              = regexp.MustCompile(`(?i)(?:\.Podfile|Podfile)`)
)

// PlistPermission holds data about how the app will use certain permissions
type PlistPermission struct {
	Name  string `json:"name"`
	Usage string `json:"usage"`
}

// ATSDomain is a domain put in the exceptions settings for App Transport Security
type ATSDomain struct {
	Name                    string `json:"name"`
	RequiresFowardSecrecy   bool   `json:"requiresFowardSecrecy"`  // NSExceptionRequiresForwardSecrecy
	IncludesSubdomains      bool   `json:"includesSubdomains"`     // NSIncludesSubdomains
	AllowsInsecureHTTPLoads bool   `json:"allowInsecureHTTPLoads"` // NSTemporaryExceptionAllowsInsecureHTTPLoads
}

// ATS holds data about rules in the ATS section
type ATS struct {
	AllowArbitraryLoads bool        `json:"arbitraryLoads"`   // NSAllowsArbitraryLoads
	ExceptionDomains    []ATSDomain `json:"exceptionDomains"` // NSExceptionDomains
}

// Plist structure holds data in the Property List
type Plist struct {
	Compiler        string `json:"compiler"`         // DTCompiler
	PlatformName    string `json:"platformName"`     // DTPlatformName
	PlatformBuild   string `json:"platformBuild"`    // DTPlatformBuild
	PlatformVersion string `json:"platformVersion"`  // DTPlatformVersion
	XCodeVersion    string `json:"xcodeVersion"`     // DTXcode
	XCodeBuild      string `json:"xcodeBuildNumber"` // DTXcodeBuild
	SDKName         string `json:"sdkName"`          // DTSDKName
	SDKBuild        string `json:"DTSDKBuild"`       // DTSDKBuild

	BundleName     string `json:"bundleName"`     // CFBundleName
	BundleVersion  string `json:"bundleVersion"`  // CFBundleVersion
	ExecutableName string `json:"executableName"` // CFBundleExecutable
	DisplayName    string `json:"displayName"`    // CFBundleDisplayName
	AppIdentifier  string `json:"appIdentifier"`  // CFBundleIdentifier
	PackageType    string `json:"packageType"`    // CFBundlePackageType

	MinimumOSVersion string `json:"minOSVersion"` // MinimumOSVersion

	Permissions        []PlistPermission `json:"permissions"`        // NS*UsageDescription section
	ATS                ATS               `json:"ats"`                // NSAppTransportSecurity section
	SupportedPlatforms []string          `json:"supportedPlatforms"` // CFBundleSupportedPlatforms section
}

type IOSAnalyzer struct {
	logger *log.Logger
}

func NewIosAnalyzer(logger *log.Logger) IOSAnalyzer {
	return IOSAnalyzer{
		logger: logger,
	}
}

func (a IOSAnalyzer) Analyze(ctx context.Context, dir string) (report.Reporter, error) {
	var r report.IOSReporter

	if err := a.analyzeSource(ctx, &r, dir); err != nil {
		return nil, err
	}

	return r, nil
}

func (a IOSAnalyzer) analyzeSource(ctx context.Context, r *report.IOSReporter, dir string) error {
	a.logger.Println("Analysing IOS libraries")
	libraries, err := a.extracLibraries(dir)
	if err != nil {
		return err
	}
	r.Libraries = libraries

	a.logger.Println("Analysing IOS plist files")
	if err := a.analyzePlist(dir, r); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		a.logger.Printf("Not found plist files at %s\n", dir)
	}

	return nil
}

func (a IOSAnalyzer) analyzePlist(dir string, rep *report.IOSReporter) error {
	files, err := engine.FindInputFiles(dir, true, findInfoFiles)
	if err != nil {
		return err
	}
	if len(files) == 0 {
		return fmt.Errorf("info %w", os.ErrNotExist)
	}

	var actualAppDir engine.InputFile

	for _, file := range files {
		if file.IsDir {
			if strings.Contains(file.Name, ".xcodeproj") {
				if actualAppDir.PhysicalPath == "" {
					actualAppDir = file
					continue
				} else if len(actualAppDir.PhysicalPath) > len(file.PhysicalPath) {
					actualAppDir = file
				}
			}
		}
	}
	if len(actualAppDir.PhysicalPath) == 0 {
		return fmt.Errorf("info %w", os.ErrNotExist)
	}

	rep.IOSInfo.AppName = strings.Split(actualAppDir.Name, ".xcodeproj")[0]
	mainAppDir := strings.Split(actualAppDir.PhysicalPath, ".xcodeproj")[0]

	mainAppFiles, err := engine.FindInputFiles(mainAppDir, false, findPListFiles)
	if err != nil {
		return err
	}

	for _, mainAppFile := range mainAppFiles {
		results := extractBundleID.FindStringSubmatch(mainAppFile.Content)

		if results != nil {
			rep.IOSInfo.BinaryID = results[1]
		}
	}

	return nil
}

func (a IOSAnalyzer) extracLibraries(dir string) ([]report.Library, error) {
	libraries := make([]report.Library, 0)

	podfileLibraries, err := a.extractLibsFromPodfiles(dir)
	if err != nil {
		return nil, err
	}
	libraries = append(libraries, podfileLibraries...)

	cartfileLibraries, err := a.extractLibsFromCartfiles(dir)
	if err != nil {
		return nil, err
	}

	libraries = append(libraries, cartfileLibraries...)

	return libraries, nil
}

func (a IOSAnalyzer) extractLibsFromCartfiles(dir string) ([]report.Library, error) {
	libraries := make([]report.Library, 0)

	files, err := engine.FindInputFiles(dir, false, isCartfileResolved)
	if err != nil {
		return nil, err
	}

	if len(files) <= 0 {
		// If we do not find a Cartfile.resolved, use the Cartfile instead
		files, err = engine.FindInputFiles(dir, false, isCartfile)
		if err != nil {
			return nil, err
		}
	}

	for _, file := range files {
		libs, err := a.extractLibsFromCartfile(file)
		if err != nil {
			return nil, err
		}

		libraries = append(libraries, libs...)
	}

	return libraries, nil
}

func (a IOSAnalyzer) extractLibsFromPodfiles(dir string) ([]report.Library, error) {
	libraries := make([]report.Library, 0)

	files, err := engine.FindInputFiles(dir, false, isPodfile)

	if err != nil {
		return nil, err
	}

	for _, file := range files {
		libs, err := extractLibsFromPodfile(file)

		if err != nil {
			return nil, err
		}

		libraries = append(libraries, libs...)
	}

	return libraries, nil
}

func (a IOSAnalyzer) extractLibsFromCartfile(file engine.InputFile) (libraries []report.Library, err error) {
	libs := extractLibsFromFile(file.Content, extractLibraryFromCartfile)

	for _, lib := range libs {
		library := report.Library{
			Name:   lib[2],
			Source: lib[1],
		}

		if lib[3] != "" {
			library.Version = lib[3]
		} else if lib[4] != "" {
			library.Version = lib[4]
		} else {
			library.Version = "latest"
		}

		libraries = append(libraries, library)
	}

	return
}

func extractLibsFromFile(content string, extractor *regexp.Regexp) [][]string {
	return extractor.FindAllStringSubmatch(content, -1)
}

func extractLibsFromPodfile(file engine.InputFile) ([]report.Library, error) {
	libraries := make([]report.Library, 0)

	libs := extractLibsFromFile(file.Content, extractLibraryFromPodfile)

	for _, lib := range libs {
		library := report.Library{
			Name:   lib[1],
			Source: "CocoaPod",
		}

		if lib[2] != "" {
			library.Version = strings.TrimSpace(lib[2])
		} else {
			library.Version = "latest"
		}

		libraries = append(libraries, library)
	}

	return libraries, nil
}

func isMacosx(path string) bool {
	return strings.Contains(path, "__MACOSX")
}

func isPodfile(path string) bool {
	// Ignore __MACOSX files since it's generally metadata
	if isMacosx(path) {
		return false
	}
	return podfileFilter.MatchString(path)
}

func isCartfileResolved(path string) bool {
	// Ignore __MACOSX files since it's generally metadata
	if isMacosx(path) {
		return false
	}
	return cartfileResolverFilter.MatchString(path)
}

func isCartfile(path string) bool {
	// Ignore __MACOSX files since it's generally metadata
	if isMacosx(path) {
		return false
	}
	return cartfileFilter.MatchString(path)
}

func findInfoFiles(path string) bool {
	// Ignore __MACOSX files since it's generally metadata
	if isMacosx(path) {
		return false
	}
	return informativeFilesFilter.MatchString(path)
}

func findPListFiles(path string) bool {
	// Ignore __MACOSX files since it's generally metadata
	if isMacosx(path) {
		return false
	}

	return plistFilesFilter.MatchString(path)
}
