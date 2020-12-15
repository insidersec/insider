package engine

import (
	"regexp"
	"strings"

	"github.com/insidersec/insider/report"
)

var (
	urlExtractor = regexp.MustCompile(`((?:http|https)://(?:[\w_-]+(?:(?:\.[\w_-]+)+))(?:[\w.,@?^=%&:/~+#-]*[\w@?^=%&/~+#-])?)`)
	urlFilter    = regexp.MustCompile(`(apple|google|android|microsoft|npmjs|yarnpkg)(\.com|\.org)`)

	urlAuthExtractor = regexp.MustCompile(`((?:http|https)://(?:[\w_-]+(?::[\w_-]+)+)(?:[\w.,@?^=%&:/~+#-]*[\w@?^=%&/~+#-])?)`)

	emailExtractor = regexp.MustCompile(`(?:[A-Za-z0-9!#$%&'*+/=?^_\x60{|}~\-\.])+@[A-Za-z0-9]+(?:\.[A-Za-z]{2,})+`)
	emailFilter    = regexp.MustCompile(`.*\.png`)
)

func AnalyzeDRA(path, content string) []report.DRA {
	dras := make([]report.DRA, 0)

	urls := extractURLs(content)
	dras = append(dras, addReportDRADataByType("url", path, urls)...)

	emails := extractEmails(content)
	dras = append(dras, addReportDRADataByType("email", path, emails)...)

	auths := extractURLAuth(content)
	dras = append(dras, addReportDRADataByType("url auth", path, auths)...)

	return dras
}

func extractURLAuth(content string) []string {
	return extracDRAs(urlAuthExtractor, content)
}

func extracDRAs(extractor *regexp.Regexp, content string, filters ...func(s string) bool) []string {
	result := make([]string, 0)
	finds := extractor.FindAllString(content, -1)

finds:
	for _, find := range finds {
		for _, filter := range filters {
			if filter(find) {
				continue finds
			}
		}
		result = append(result, find)
	}
	return result
}

func extractEmails(content string) []string {
	return extracDRAs(emailExtractor, content, emailFilter.MatchString, func(s string) bool {
		if idx := strings.Index(s, "@"); idx >= 0 {
			return len(s[:idx-1]) < 2
		}
		return false
	})
}

func extractURLs(content string) (result []string) {
	return extracDRAs(urlExtractor, content, urlFilter.MatchString)
}

func addReportDRADataByType(draType, filepath string, dras []string) (dra []report.DRA) {
	for _, data := range dras {
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
			strings.Contains(data, "git@") ||
			strings.Contains(data, "spec") {
			continue
		}

		draData := report.DRA{
			Data:     data,
			Type:     draType,
			FilePath: filepath,
		}

		dra = append(dra, draData)
	}

	return
}
