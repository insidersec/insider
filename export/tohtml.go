package export

import (
	"bytes"
	"fmt"
	"html/template"
	"insider/util"
	"log"
	"os"
	"time"
)

func createHTMLFile(file string, content string) {
	f, err := os.Create(file)
	if err != nil {
		log.Println(err)
		return
	}
	l, err := f.WriteString(content)
	if err != nil {
		log.Println(err)
		err := f.Close()
		if err != nil {
			log.Fatalln(err)
			return
		}
		return
	}
	pwd, _ := os.Getwd()
	log.Printf("Html Report %s/%s", pwd, file)
	log.Println("Html Report", util.ByteCountSI(int64(l)), "bytes written successfully")
	err = f.Close()
	if err != nil {
		log.Println(err)
		return
	}
}

func ToHtml(report interface{}, lang string, ignoreWarnings bool) {
	tmpl, err := template.New("report").Parse(GetTemplate(lang))
	if err != nil {
		log.Println(err)
		return
	}
	var tpl bytes.Buffer
	err = tmpl.Execute(&tpl, report)
	if err != nil {
		log.Println(err)
		return
	}

	var reportname string
	if !ignoreWarnings {
		currentTime := time.Now()
		reportname = fmt.Sprintf("report-%v.html", currentTime.Format("20060102150405"))
	} else {
		reportname = "report.html"
	}

	createHTMLFile(reportname, tpl.String())
	util.DownloadFile("style.css", "https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css")
}
