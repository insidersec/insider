package export

import (
	"bytes"
	"fmt"
	"html/template"
	"github.com/insidersec/insider/util"
	"log"
	"os"
	"time"
)

func createHTMLFile(file string, content string) error {
	f, err := os.Create(file)
	if err != nil {
		return err
	}

	defer func() {
		if err := f.Close(); err != nil {
			log.Printf("Error on defer to close file: %v\n", err)
		}
	}()

	l, err := f.WriteString(content)
	if err != nil {
		return err
	}
	pwd, err := os.Getwd()
	if err != nil {
		return err
	}

	log.Printf("Html Report %s/%s", pwd, file)
	log.Println("Html Report", util.ByteCountSI(int64(l)), "bytes written successfully")

	return nil
}

func ToHtml(report interface{}, lang string, ignoreWarnings bool) error {
	tmpl, err := template.New("report").Parse(GetTemplate(lang))
	if err != nil {
		return err
	}
	var tpl bytes.Buffer
	if err := tmpl.Execute(&tpl, report); err != nil {
		return err
	}

	var reportname string
	if !ignoreWarnings {
		currentTime := time.Now()
		reportname = fmt.Sprintf("report-%v.html", currentTime.Format("20060102150405"))
	} else {
		reportname = "report.html"
	}

	if err := createHTMLFile(reportname, tpl.String()); err != nil {
		return err
	}
	return util.DownloadFile("style.css", "https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css")
}
