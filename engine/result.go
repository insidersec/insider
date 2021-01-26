package engine

import (
	"fmt"

	"github.com/insidersec/insider/report"
)

type Result struct {
	AverageCVSS     float64
	SecurityScore   float64
	Lines           int
	Size            int64
	Vulnerabilities []report.Vulnerability
}

func (r Result) ToReporter(dir string, base report.Reporter) (report.Reporter, error) {
	switch v := base.(type) {
	case report.Report:
		return r.toDefaultReporter(dir, v)
	case report.AndroidReporter:
		return r.toAndroidReporter(dir, v)
	case report.IOSReporter:
		return r.toIosReporter(dir, v)
	default:
		return nil, fmt.Errorf("report type %T not recognized", v)
	}
}

func (result *Result) toDefaultReporter(dir string, r report.Report) (report.Reporter, error) {
	none, low, medium, high, critical, total := cvssRatings(result.Vulnerabilities)
	r.Info.AverageCVSS = result.AverageCVSS
	r.Info.SecurityScore = result.SecurityScore
	r.Info.NumberOfLines = result.Lines
	r.Info.Size = fmt.Sprintf("%d Bytes", result.Size)
	r.Vulnerabilities = result.Vulnerabilities
	r.None = none
	r.Low = low
	r.Medium = medium
	r.High = high
	r.Critical = critical
	r.Total = total

	return r, nil
}

func (result *Result) toAndroidReporter(dir string, r report.AndroidReporter) (report.Reporter, error) {
	none, low, medium, high, critical, total := cvssRatings(result.Vulnerabilities)
	r.AndroidInfo.AverageCVSS = result.AverageCVSS
	r.AndroidInfo.SecurityScore = result.SecurityScore
	r.AndroidInfo.NumberOfLines = result.Lines
	r.AndroidInfo.Size = fmt.Sprintf("%d Bytes", result.Size)
	r.Vulnerabilities = result.Vulnerabilities
	r.None = none
	r.Low = low
	r.Medium = medium
	r.High = high
	r.Critical = critical
	r.Total = total

	return r, nil
}

func (result *Result) toIosReporter(dir string, r report.IOSReporter) (report.Reporter, error) {
	none, low, medium, high, critical, total := cvssRatings(result.Vulnerabilities)
	r.IOSInfo.AverageCVSS = result.AverageCVSS
	r.IOSInfo.SecurityScore = result.SecurityScore
	r.IOSInfo.NumberOfLines = result.Lines
	r.IOSInfo.Size = fmt.Sprintf("%d Bytes", result.Size)
	r.Vulnerabilities = result.Vulnerabilities
	r.None = none
	r.Low = low
	r.Medium = medium
	r.High = high
	r.Critical = critical
	r.Total = total

	return r, nil
}

func cvssRatings(vulnerabilities []report.Vulnerability) (none, low, medium, high, critical, total int) {
	for _, v := range vulnerabilities {
		if v.CVSS == 0 {
			none++
		}
		if v.CVSS > 0 && v.CVSS < 3.9 {
			low++
		}
		if v.CVSS >= 4 && v.CVSS < 6.9 {
			medium++
		}
		if v.CVSS >= 7 && v.CVSS <= 8.9 {
			high++
		}
		if v.CVSS >= 9 && v.CVSS <= 10 {
			critical++
		}
	}
	return none, low, medium, high, critical, (none + low + medium + high + critical)
}
