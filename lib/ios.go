package lib

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"insider/analyzers"
	"insider/lexer"
	"insider/models/reports"
	"insider/visitor"
)

func loadPlistData() (permissions []reports.IOSPermission, err error) {
	fullPath := os.Getenv("GOPATH")
	projectPrefix := "src/inmetrics/insider"

	manifestData, err := ioutil.ReadFile(
		filepath.Join(fullPath, projectPrefix, "analyzers/plist_data.json"),
	)

	if err != nil {
		return permissions, err
	}

	err = json.Unmarshal(manifestData, &permissions)

	if err != nil {
		return permissions, err
	}

	return permissions, nil
}

// AnalyzeIOSBinary takes care about the special internal structure of a Mach-O object
// from a decompiled IPA
func AnalyzeIOSBinary(dirname, sastID string, report *reports.IOSReport, lang string) error {
	log.Println("Found decompiled app, searching for special Info.plist structure")
	binaryRules, err := lexer.LoadRules("iosBinary", lang)

	if err != nil {
		return err
	}

	plist, err := analyzers.GetPlistFromJSON(dirname)

	if err != nil {
		return err
	}

	permissionData, err := loadPlistData()

	if err != nil {
		return err
	}

	report.IOSInfo.SastID = sastID
	report.IOSInfo.AppName = plist.DisplayName
	report.IOSInfo.Build = plist.BundleVersion
	report.IOSInfo.TargetVersion = plist.SDKName
	report.IOSInfo.BinaryID = plist.AppIdentifier
	report.IOSInfo.BinaryType = plist.PackageType
	report.IOSInfo.MinimumOSVersion = plist.MinimumOSVersion
	report.IOSInfo.SupportedPlatforms = strings.Join(plist.SupportedPlatforms, ", ")

	// Interpolate the data about permission descriptions and
	// the data found inside the Plist file from the app
	for _, foundPermission := range plist.Permissions {
		for _, rawPermissionData := range permissionData {
			if foundPermission.Name == rawPermissionData.Name {
				permission := rawPermissionData
				permission.Reason = foundPermission.Usage
				permission.SastID = sastID

				report.Permissions = append(report.Permissions, permission)
			}
		}
	}

	// Handles ATS exceptions as vulnerabilities
	for _, exceptionDomain := range plist.ATS.ExceptionDomains {
		baseMessage := "Foi encontrado uma exceção para o domínio %s nas regras de ATS. É necessário sempre revisar quais dominios o app está permitido à acessar usando o protocolo HTTP, pois essas informações podem ser interceptadas e lidas em texto puro por um possível atacante ou servidor de interceptação (Proxy), tornando sempre recomendado ativar o ATS (App Transport Security) nas configurações do aplicativo para qualquer dominio que não necessite explicitamente desse protocolo."
		vulnerability := reports.Vulnerability{
			SastID:       sastID,
			CWE:          "CWE-319",
			Rank:         "média",
			CVSS:         2,
			Class:        "Info.plist",
			ShortMessage: "Foi encontrada uma exceção nas regras de ATS (App Transport Security) para um domínio",
		}

		longMessage := fmt.Sprintf(baseMessage, exceptionDomain.Name)

		rawEvidenceHash := fmt.Sprintf("%s:%s", "Info.plist", exceptionDomain.Name)

		vulnerability.VulnerabilityID = fmt.Sprintf("%x", md5.Sum([]byte(rawEvidenceHash)))

		if exceptionDomain.RequiresFowardSecrecy {
			longMessage = fmt.Sprintf("%s Esse domínio também está listado como domínio que o aplicativo pode seguir em redirecionamentos HTTP inseguros.", longMessage)
		}

		if exceptionDomain.IncludesSubdomains {
			longMessage = fmt.Sprintf("%s O aplicativo também está confiando em todos os subdomínios atrelados a esse domínio raíz.", longMessage)
		}

		if exceptionDomain.AllowsInsecureHTTPLoads {
			longMessage = fmt.Sprintf("%s Esse domínio também está autorizado a baixar recursos externos usando o protocolo HTTP, que pode ser um risco alto caso esteja sendo usado dentro de uma WebView.", longMessage)
		}

		vulnerability.LongMessage = longMessage

		report.Vulnerabilities = append(report.Vulnerabilities, vulnerability)
	}

	// Loads libs.e file and parses it
	libsFound, err := analyzers.ParseLibsFile(dirname, sastID)

	if err != nil {
		return err
	}

	for _, library := range libsFound {
		if !strings.Contains(library.Source, "Shared Library") || !strings.Contains(library.Source, "System Library") {
			report.Libraries = append(report.Libraries, library)
		}
	}

	err = analyzers.ParseHeaderFile(dirname, report)

	if err != nil {
		return err
	}

	// AnalyzeSymbolTable searches the given `dirname` folder for a file
	// called "dynsymtable.e" and parses it searching for vulnerable functions
	symbolTableFilename := filepath.Join(dirname, "dynsymtable.e")

	symbolTable, err := ioutil.ReadFile(symbolTableFilename)

	if err != nil {
		return err
	}

	fileForAnalyze := visitor.NewInputFile(dirname, symbolTableFilename, symbolTable)

	fileSummary := analyzers.AnalyzeFile(fileForAnalyze, binaryRules)

	highestCVSS := 0.0
	for _, finding := range fileSummary.Findings {
		vulnerability := ConvertFindingToReport(
			fileForAnalyze.Name,
			fileForAnalyze.DisplayName,
			finding,
		)

		if vulnerability.CVSS > highestCVSS {
			highestCVSS = vulnerability.CVSS
		}

		vulnerability.SastID = sastID

		report.Vulnerabilities = append(report.Vulnerabilities, vulnerability)
	}

	report.IOSInfo.AverageCVSS = highestCVSS
	report.IOSInfo.SecurityScore = CalculateSecurityScore(report.IOSInfo.AverageCVSS)
	report.IOSInfo.SastID = sastID

	return nil
}

// AnalyzeIOSSource self-explained
func AnalyzeIOSSource(dirname, sastID string, report *reports.IOSReport, lang string) error {

	files, rules, err := LoadsFilesAndRules(dirname, "ios", lang)

	if err != nil {
		return err
	}

	appSize, err := analyzers.GetUnpackedAppSize(dirname)

	if err != nil {
		return err
	}

	report.IOSInfo.Size = fmt.Sprintf("%s MB", strconv.Itoa(appSize))

	log.Println("Starting extracting hardcoded information")

	err = ExtractHardcodedInfo(dirname, sastID, report)

	if err != nil {
		return err
	}

	log.Println("Finished hardcoded information extraction")

	highestCVSS := 0.0

	for _, file := range files {
		fileContent, err := ioutil.ReadFile(file)

		if err != nil {
			return err
		}

		fileForAnalyze := visitor.NewInputFile(dirname, file, fileContent)

		// See analyzers/static.go:156
		// fileForAnalyze.Libraries = report.Libraries

		report.IOSInfo.NumberOfLines = report.IOSInfo.NumberOfLines + len(fileForAnalyze.NewlineIndexes)

		urls := extractURLs(report.GetDRAURLs(), fileForAnalyze.Content)
		emails := extractEmails(report.GetDRAEmails(), fileForAnalyze.Content)

		report.AddDRAURLs(urls, fileForAnalyze.PhysicalPath)
		report.AddDRAEmails(emails, fileForAnalyze.PhysicalPath)

		fileSummary := analyzers.AnalyzeFile(fileForAnalyze, rules)

		for _, finding := range fileSummary.Findings {
			vulnerability := ConvertFindingToReport(
				fileForAnalyze.Name,
				fileForAnalyze.DisplayName,
				finding,
			)

			// Now we search other files affected by this vulnerability
			for _, affectedFile := range files {
				affectedFileContent, err := ioutil.ReadFile(affectedFile)

				if err != nil {
					return err
				}

				affectedInputFile := visitor.NewInputFile(dirname, affectedFile, affectedFileContent)

				if affectedInputFile.Uses(fileForAnalyze.ImportReference) {
					vulnerability.AffectedFiles = append(vulnerability.AffectedFiles, affectedInputFile.DisplayName)
				}
			}

			if vulnerability.CVSS > highestCVSS {
				highestCVSS = vulnerability.CVSS
			}

			vulnerability.SastID = sastID

			report.Vulnerabilities = append(report.Vulnerabilities, vulnerability)
		}
	}

	report.IOSInfo.AverageCVSS = highestCVSS
	report.IOSInfo.SecurityScore = CalculateSecurityScore(report.IOSInfo.AverageCVSS)
	report.IOSInfo.SastID = sastID

	log.Printf("Scanned %d lines", report.IOSInfo.NumberOfLines)

	return nil
}

// ExtractLibrariesFromFiles self-explained
func ExtractLibrariesFromFiles(dirname, sastID string) (libraries []reports.Library, err error) {
	podfileLibraries, err := analyzers.ExtractLibsFromPodfiles(dirname)

	if err != nil {
		return
	}

	for _, library := range podfileLibraries {
		library.SastID = sastID
		libraries = append(libraries, library)
	}

	cartfileLibraries, err := analyzers.ExtractLibsFromCartfiles(dirname)

	if err != nil {
		return
	}

	for _, library := range cartfileLibraries {
		library.SastID = sastID
		libraries = append(libraries, library)
	}

	return
}
