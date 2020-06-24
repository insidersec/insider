package export

import (
	"bytes"
	"html/template"
	"insider/util"
	"log"
	"os"
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

func ToHtml(report interface{}, lang string) {
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

	createHTMLFile("report.html", tpl.String())
	util.DownloadFile("style.css", "https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css")
}
