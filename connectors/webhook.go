package connectors

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
)

// WebhookConnector holds data about the special
// webhook-based log system.
type WebhookConnector struct {
	channelID     string
	username      string
	webhookTarget string

	httpClient *http.Client
}

// NewWebhookConnector creates and return a new WebhookConnector
func NewWebhookConnector() (connector WebhookConnector) {
	connector.webhookTarget = os.Getenv("WEBHOOK_ADDRESS")
	connector.channelID = os.Getenv("WEBHOOK_CHANNEL")
	connector.username = os.Getenv("WEBHOOK_USERNAME")

	connector.httpClient = NewHTTPClient()

	return
}

// ReportError posts a message to the configured feed
// about the ongoing progress of a analysis.
func (connector *WebhookConnector) ReportError(correlationID, sastID, data string) (err error) {
	if os.Getenv("EVE_DEBUG") != "" {
		return nil
	}

	defaultMessage := fmt.Sprintf(`
		Error:
		Mensagem -> %s
		Correlation ID -> %s
		SAST ID -> %s
	`, data, correlationID, sastID)

	payload := map[string]string{
		"text":     defaultMessage,
		"username": connector.username,
		"channel":  connector.channelID,
	}

	rawPayload, err := json.Marshal(payload)

	if err != nil {
		return
	}

	resp, err := connector.httpClient.PostForm(
		connector.webhookTarget,
		url.Values{
			"payload": []string{string(rawPayload)},
		},
	)

	if err != nil {
		return
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return errors.New("Error posting log message")
	}

	return nil
}
