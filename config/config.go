package config

import (
	"log"
	"os"
	"path/filepath"
	"strings"
)

type FileListControl struct {
	Tech    string `json:"tech"`
	Exclude struct {
		Dra struct {
			Folder []string `json:"folder"`
			File   []string `json:"file"`
		} `json:"dra"`
	} `json:"exclude"`
}

func resolveToRuleDataFolder(filename string) string {
	fullPath, _ := os.Getwd()
	return filepath.Join(fullPath, filename)
}

// remove files from analize
func CleanListFiles(tech string, files *[]string) error {

	newfiles := make([]string, 0)
	var flc FileListControl

	switch tech {
	case "java":
		flc.Tech = "java"
		flc.Exclude.Dra.Folder = []string{""}
		flc.Exclude.Dra.File = []string{"pow.xml"}

	case "ios":
		flc.Tech = "ios"
		flc.Exclude.Dra.Folder = []string{"pods"}
		flc.Exclude.Dra.File = []string{"", ""}

	case "javascript":
		flc.Tech = "javascript"
		flc.Exclude.Dra.Folder = []string{"node_modules"}
		flc.Exclude.Dra.File = []string{"package.json", "package-lock.json"}
	}

	log.Println("Removing:", flc.Exclude.Dra.File, "from file list from", tech, "tech")
	log.Println("Removing:", flc.Exclude.Dra.Folder, "from file list from", tech, "tech")

	//create a new file list from original list
	for _, value := range *files {

		// checking if folder is not allowed
		var checkfolder = 0
		for _, v := range flc.Exclude.Dra.Folder {
			if strings.Contains(value, v+"/") {
				log.Println("Folder Found ", v+"/")
				log.Println(value)
				checkfolder += 1
			}
		}

		// if folder is allowed
		if checkfolder == 0 {
			// checking if file is not allowed
			var checkfile = 0
			for _, v := range flc.Exclude.Dra.File {
				v = strings.Replace(v, "*", "", -1)
				if strings.Contains(value, v) {
					checkfile += 1
				}
			}
			// if ok == 0 then no file to remove from original list
			if checkfile == 0 {
				newfiles = append(newfiles, value)
			}
		}
	}
	// set files with clean file list
	//log.Println(newfiles)
	*files = newfiles
	return nil
}
