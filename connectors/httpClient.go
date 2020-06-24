package connectors

import (
	"net/http"
	"time"
)

// NewHTTPClient creates a new HTTP client with the default configurations
func NewHTTPClient() *http.Client {
	timeoutConfig, _ := time.ParseDuration("20s")

	return &http.Client{
		Timeout: timeoutConfig,
	}
}
