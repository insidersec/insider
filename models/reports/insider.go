package reports

import (
	"log"
	"strings"
)

const (
	draEmailType string = "email"
	draURLType   string = "url"
)

// DRA stands for Digital Risks anaytics, a key part of analyzing
// the overall data exposure about the application
type DRA struct {
	Data     string `json:"dra"`
	SastID   string `json:"sast,omitempty"`
	Type     string `json:"type"`
	FilePath string `json:"file"`
}

// LibraryVulnerability is a structure to hold data
// about vulnerabilities found on libraries
// to Insider`s Console
type LibraryVulnerability struct {
	CWE           string `json:"cwe"`
	CVEs          string `json:"cves"`
	SastID        string `json:"sast"`
	Title         string `json:"title"`
	Severity      string `json:"severity"`
	ID            int    `json:"advisoryId"`
	Description   string `json:"description"`
	Recomendation string `json:"recomendation"`
}

// Vulnerability is the default structure to represent a potentially
// dangerous piece code inside the source analyzed.
type Vulnerability struct {
	CVSS            float64  `json:"cvss"`
	CWE             string   `json:"cwe,omitempty"`
	Rank            string   `json:"rank,omitempty"`
	Line            int      `json:"line,omitempty"`
	SastID          string   `json:"sast,omitempty"`
	Class           string   `json:"class,omitempty"`
	VulnerabilityID string   `json:"vul_id,omitempty"`
	Method          string   `json:"method,omitempty"`
	Column          int      `json:"column,omitempty"`
	Category        string   `json:"category,omitempty"`
	Priority        string   `json:"priority,omitempty"`
	LongMessage     string   `json:"longMessage,omitempty"`
	ClassMessage    string   `json:"classMessage,omitempty"`
	ShortMessage    string   `json:"shortMessage,omitempty"`
	MethodMessage   string   `json:"methodMessage,omitempty"`
	AffectedFiles   []string `json:"affectedFiles,omitempty"`
}

// Library is the default representation of a library found inside
// analized source.
type Library struct {
	SastID               string `json:"sast,omitempty"`
	Name                 string `json:"name,omitempty"`
	Version              string `json:"current,omitempty"`
	Source               string `json:"source,omitempty"`
	CompatibilityVersion string `json:"compatiblityVersion,omitempty"`
}

// SASTInfo holds generic information about the overall report
type SASTInfo struct {
	Name          string  `json:"name,omitempty"`
	Version       string  `json:"version,omitempty"`
	SastID        string  `json:"sast,omitempty"`
	AverageCVSS   float64 `json:"averageCvss,omitempty"`
	SecurityScore float32 `json:"securityScore,omitempty"`
	MD5           string  `json:"md5,omitempty"`
	Size          string  `json:"size,omitempty"`
	SHA1          string  `json:"sha1,omitempty"`
	SHA256        string  `json:"sha256,omitempty"`
	NumberOfLines int     `json:"numberOfLines,omitempty"`
}

// Report generic for uploading to Axiom
type Report struct {
	DRA             []DRA                  `json:"dra"`
	LibraryIssues   []LibraryVulnerability `json:"sca,omitempty"`
	Info            SASTInfo               `json:"sast,omitempty"`
	Libraries       []Library              `json:"libraries,omitempty"`
	Vulnerabilities []Vulnerability        `json:"vulnerabilities,omitempty"`
}

func getReportDRADataByType(dra []DRA, draType string) (data []string) {
	for _, draData := range dra {
		if draData.Type == draType {
			data = append(data, draData.Data)
		}
	}

	return
}

func addReportDRADataByType(draType, sastID, filepath string, rawData []string) (dra []DRA) {
	for _, data := range rawData {
		if strings.Contains(data, ".jpg") ||
			strings.Contains(data, ".jpeg") ||
			strings.Contains(data, ".png") ||
			strings.Contains(data, ".gif") ||
			strings.Contains(data, ".yaml") ||
			strings.Contains(data, ".yml") ||
			strings.Contains(data, ".exe") ||
			strings.Contains(data, ".md") ||
			strings.Contains(data, ".markdown") ||
			strings.Contains(data, "test") ||
			strings.Contains(data, "spec") {
			continue
		}

		draData := DRA{
			Data:     data,
			SastID:   sastID,
			Type:     draType,
			FilePath: filepath,
		}

		dra = append(dra, draData)
	}

	return
}

// SetSastID sets the SastID for the given report
func (report *Report) SetSastID(sastID string) {
	report.Info.SastID = sastID
}

// GetDRAEmails returns the list of already found emails in data extraction
func (report *Report) GetDRAEmails() []string {
	return getReportDRADataByType(report.DRA, draEmailType)
}

// GetDRAURLs returns the list of already found URLs in data extraction
func (report *Report) GetDRAURLs() []string {
	return getReportDRADataByType(report.DRA, draURLType)
}

// AddDRAEmails includes the extracted emails in the report internal list
func (report *Report) AddDRAEmails(emails []string, filepath string) {
	draEmails := addReportDRADataByType(draEmailType, report.Info.SastID, filepath, emails)

	report.DRA = append(report.DRA, draEmails...)
}

// AddDRAURLs includes the extracted URLs in the report internal list
func (report *Report) AddDRAURLs(urls []string, filepath string) {
	draURLs := addReportDRADataByType(draURLType, report.Info.SastID, filepath, urls)

	report.DRA = append(report.DRA, draURLs...)
}

func unique(slice []DRA) []DRA {
	keys := make(map[string]bool)
	list := []DRA{}
	for _, entry := range slice {
		if _, value := keys[entry.Data]; !value {
			keys[entry.Data] = true
			list = append(list, entry)
		}
	}
	return list
}

// SanitizeDRA cleans up the DRA list
func (report *Report) SanitizeDRA() {
	report.DRA = unique(report.DRA)
}

type HMLT struct {
	High   int
	Medium int
	Low    int
	Total  int
}

type newreport struct {
	DRA             []DRA
	Libraries       []Library
	Vulnerabilities []Vulnerability
	SecurityScore   float32
	High            int
	Medium          int
	Low             int
	Total           int
}

type DoHtmlReportInterface interface {
	Create() newreport
}

func DoHtmlReport(r DoHtmlReportInterface) newreport {
	return r.Create()
}

func getHighMedionLow(r []Vulnerability) (int, int, int, int) {
	var high int = 0
	var medium int = 0
	var low int = 0

	for _, v := range r {
		if v.CVSS >= 0 && v.CVSS < 3.9 {
			medium++
		}
		if v.CVSS > 4 && v.CVSS < 6.9 {
			low++
		}
		if v.CVSS > 7 && v.CVSS < 10 {
			high++
		}
	}
	return high, medium, low, high + medium + low
}

func (report Report) Create() newreport {

	high, medium, low, total := getHighMedionLow(report.Vulnerabilities)
	t := newreport{
		DRA:             report.DRA,
		Libraries:       report.Libraries,
		Vulnerabilities: report.Vulnerabilities,
		SecurityScore:   report.Info.SecurityScore,
		High:            high,
		Medium:          medium,
		Low:             low,
		Total:           total,
	}
	return t
}

func (report AndroidReport) Create() newreport {

	high, medium, low, total := getHighMedionLow(report.Vulnerabilities)

	t := newreport{
		DRA:             report.DRA,
		Libraries:       report.Libraries,
		Vulnerabilities: report.Vulnerabilities,
		SecurityScore:   report.AndroidInfo.SecurityScore,
		High:            high,
		Medium:          medium,
		Low:             low,
		Total:           total,
	}
	return t
}

func (report IOSReport) Create() newreport {

	high, medium, low, total := getHighMedionLow(report.Vulnerabilities)

	t := newreport{
		DRA:             report.DRA,
		Libraries:       report.Libraries,
		Vulnerabilities: report.Vulnerabilities,
		SecurityScore:   report.IOSInfo.SecurityScore,
		High:            high,
		Medium:          medium,
		Low:             low,
		Total:           total,
	}
	return t
}

func ResumeReport(r newreport) {
	log.Println("-----------------------------------------------")
	log.Printf("Score Security %v/100", r.SecurityScore)
	log.Println("Vulnerability\tNumber")
	log.Printf("High\t\t%3v \n", r.High)
	log.Printf("Medium\t\t%3v \n", r.Medium)
	log.Printf("Low\t\t%3v \n", r.Low)
	log.Printf("Total\t\t%3v \n", r.Total)
	log.Println("-----------------------------------------------------------------------------------------------------------------------")
	log.Println("You are using the Insider open source version. If you like the product and want more features,")
	log.Println("visit http://insidersec.io and get to know our enterprise version.")
	log.Println("If you are a developer, then you can contribute to the improvement of the software while using an open source version")
}

func ConsoleReport(r newreport) {
	log.Println("---------------------------------------------------------------------")
	log.Printf("Score Security %v\n\n", r.SecurityScore)

	for i, k := range r.DRA {
		if i == 0 {
			log.Println("DRA - Data Risk Analytics")
		}
		log.Println("File", k.FilePath)
		log.Println("Dra", k.Data)
		log.Println("Type", k.Type)
	}
	log.Println(" ")

	for i, k := range r.Libraries {
		if i == 0 {
			log.Printf("%-20v %-10v \n", "Library", "Version")
		}
		log.Printf("%-20v %-10=v \n", k.Name, k.Version)
	}
	log.Println(" ")

	for _, k := range r.Vulnerabilities {
		log.Println("CVSS", k.CVSS)
		log.Println("Rank", k.Rank)
		log.Println("Class", k.Class)
		log.Println("VulnerabilityID", k.VulnerabilityID)
		log.Println("LongMessage", k.LongMessage)
		log.Println("ClassMessage", k.ClassMessage)
		log.Println("ShortMessage", k.ShortMessage)
		log.Println("")
	}

	log.Println("---------------------------------------------------------------------")
}
