package sources

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/1lo1lo1/subsurge/pkg/models"
)

// NewHTTPClient creates a hardened HTTP client for sources.
func NewHTTPClient(timeoutSec int) *http.Client {
	if timeoutSec <= 0 {
		timeoutSec = 30
	}
	return &http.Client{
		Timeout: time.Duration(timeoutSec) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: false},
			MaxIdleConnsPerHost: 10,
			DisableKeepAlives:   false,
		},
	}
}

// GET performs a GET request and returns the body bytes.
func GET(client *http.Client, url string, headers map[string]string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 subsurge/1.0 (+https://github.com/1lo1lo1/subsurge)")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20)) // 10 MB cap
	return body, resp.StatusCode, err
}

// emit is a helper used by sources to push a result onto a channel.
func emit(ch chan<- models.Result, domain, source string) {
	if strings.TrimSpace(domain) == "" {
		return
	}
	ch <- models.Result{
		Domain:    strings.ToLower(strings.TrimSpace(domain)),
		Source:    source,
		Timestamp: time.Now(),
	}
}

// apiKey retrieves a key from the config map.
func apiKey(cfg map[string]string, keys ...string) string {
	for _, k := range keys {
		if v, ok := cfg[k]; ok && v != "" {
			return v
		}
	}
	return ""
}

// noKey signals a missing required key.
func noKey(source string) error {
	return fmt.Errorf("source %s: API key not configured (see ~/.config/subsurge/config.yaml)", source)
}
