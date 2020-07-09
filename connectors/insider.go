package connectors

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
)

const (
	sastUpdateErrorMessage = "[ERROR]: %s while updating Insider status about SAST #%s"
	sastUpdateURL          = "%s%s/sast/%s/component/%s"
	sastResultErrorMessage = "[ERROR]: %s while uploading the result for SAST #%s"
	sastResultURL          = "%s%s/sast/%s/component/%s/%s"

	// This codes are the status code to be send
	// to Axion about the result of the analysis

	// InsiderErrorStatus is the error status
	InsiderErrorStatus = "3"
	// InsiderSuccessStatus is the success status
	InsiderSuccessStatus = "2"
)

// Auth struct
type Auth struct {
	user     string
	password string
	path     string
	token    string
}

// InsiderConnector struct
type InsiderConnector struct {
	host   string
	path   string
	auth   Auth
	client *http.Client
}

// NewInsiderConnector self-explained
func NewInsiderConnector() (insider InsiderConnector) {
	insider.host = os.Getenv("insider_host")
	insider.path = os.Getenv("insider_url")
	insider.auth = Auth{
		user:     os.Getenv("insider_user"),
		password: os.Getenv("insider_pass"),
		path:     os.Getenv("insider_url_auth"),
	}

	insider.client = NewHTTPClient()

	return
}

func (insider *InsiderConnector) getAuthentication() error {
	url := insider.host + insider.auth.path
	data := "{\"email\": \"" + insider.auth.user + "\", \"password\": \"" + insider.auth.password + "\"}"

	var jsonStr = []byte(data)

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonStr))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := insider.client.Do(req)
	if err != nil {
		return err
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if !strings.Contains(string(body), "{") {
		errorMessage := fmt.Sprintf("problem getting auth token from Axion. Message: %s", string(body))
		return errors.New(errorMessage)
	}

	tokenJSON := make(map[string]interface{})

	if err := json.Unmarshal(body, &tokenJSON); err != nil {
		return fmt.Errorf("Error while getting auth token from Axion JSON: %w", err)
	}

	token, ok := tokenJSON["token"].(string)
	if !ok {
		return errors.New("problems authenticating for report upload")
	}

	insider.auth.token = token
	return nil
}

// UpdateSASTStatus self-explained
func (insider *InsiderConnector) UpdateSASTStatus(componentID, sastID, version, status, log string) error {
	if os.Getenv("EVE_DEBUG") != "" {
		return nil
	}

	if err := insider.getAuthentication(); err != nil {
		return err
	}

	url := fmt.Sprintf(sastUpdateURL, insider.host, insider.path, sastID, componentID)
	data := `{"version":"` + version + `","log":"` + log + `","status":"` + status + `","resultSast": true}`

	var jsonStr = []byte(data)

	req, err := http.NewRequest("PUT", url, bytes.NewBuffer(jsonStr))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", insider.auth.token)

	resp, err := insider.client.Do(req)
	if err != nil {
		return err
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode != 200 {
		sastStatusUpdateError := fmt.Sprintf(sastUpdateErrorMessage, string(body), sastID)
		return errors.New(sastStatusUpdateError)
	}

	return nil
}

// ReportSASTResult self-explained
func (insider *InsiderConnector) ReportSASTResult(componentID, sastID, path string, findings []byte) error {
	url := fmt.Sprintf(sastResultURL, insider.host, insider.path, sastID, componentID, path)

	if os.Getenv("EVE_DEBUG") != "" {
		log.Printf("Should have sended to INSIDER => %s", url)
		return nil
	}

	if err := insider.getAuthentication(); err != nil {
		return err
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(findings))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", insider.auth.token)

	resp, err := insider.client.Do(req)
	if err != nil {
		return err
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode != 200 {
		sastUploadResultError := fmt.Sprintf(sastResultErrorMessage, string(body), sastID)
		return errors.New(sastUploadResultError)
	}

	return nil
}
