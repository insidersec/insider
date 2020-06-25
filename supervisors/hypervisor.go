package supervisors

import (
	"bytes"
	"encoding/json"
	"fmt"
	"insider/util"
	"log"
	"os"
	"strconv"
	"strings"
	"time"
)

// SourceCodeInfo holds information about the received code to analyze
type SourceCodeInfo struct {
	Path         string
	Tech         string
	SastID       string
	Version      string
	ComponentID  string
	PhysicalPath string

	// Hashing
	MD5Hash    string
	SHA1Hash   string
	SHA256Hash string
}

// reportResult will handle the logic to upload the final report about the source code
// being analyzed to somewhere it can be feed into other tools or used by hand.
// By default, in development environment it will save the report to a file in the
// current directory with the name of report-[here will be the SAST ID].json
func reportResult(bReport []byte, ignoreWarnings bool) error {

	// Running on debug mode, should avoid communication with the Console.

	var reportFilename string
	if !ignoreWarnings {
		currentTime := time.Now()
		reportFilename = fmt.Sprintf("report-%v.json", currentTime.Format("20060102150405"))
	} else {
		reportFilename = "report.json"
	}
	pwd, _ := os.Getwd()
	log.Printf("Json Report %s/%s", pwd, reportFilename)
	//log.Println("Writting report to JSON file.")

	file, err := os.OpenFile(reportFilename, os.O_CREATE|os.O_WRONLY, 0666)

	if err != nil {
		log.Println("Problems writing the report to the JSON file.")
	}

	defer file.Close()

	// Makes sure we start to write in the beginning of the file
	// and overwriting anything that was previously inside the file
	err = file.Truncate(0)

	if err != nil {
		log.Println("Problems writing the report to the JSON file.")
		return err
	}

	_, err = file.Seek(0, 0)

	if err != nil {
		log.Println("Problems writing the report to the JSON file.")
		return err
	}

	var outputBuffer bytes.Buffer

	// This will format the output according to the
	// JSON specification to be easier to read by a human

	// - the first parameter is a pointer to the output buffer
	// - the second one is the actual byte slice with the data
	// - the third is a prefix to each line in the input buffer
	// - the fourth is the actual character to be used in identation
	//    here we're using space for compatibility
	json.Indent(&outputBuffer, bReport, "", " ")

	//formattedContent, err := strconv.Unquote(strings.Replace(strconv.Quote(string(outputBuffer.Bytes())), `\\u`, `\u`, -1))
	formattedContent, err := strconv.Unquote(strings.Replace(strconv.Quote(string(outputBuffer.Bytes())), ``, ``, -1))

	if err != nil {
		log.Println("Problems writing the report to the JSON file.")
		return err
	}

	bytesWritten, err := file.Write([]byte(formattedContent))

	if err != nil {
		log.Println("Problems writing the report to the JSON file.")
		return err
	}

	log.Printf("Json Report %v bytes written successfully", util.ByteCountSI(int64(bytesWritten)))

	return nil
}
