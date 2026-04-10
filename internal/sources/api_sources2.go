package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/1lo1lo1/subsurge/pkg/models"
)

// newBasicAuthRequest creates an HTTP GET request with Basic Auth.
func newBasicAuthRequest(url, user, pass string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(user, pass)
	req.Header.Set("User-Agent", "Mozilla/5.0 subsurge/1.0")
	return req, nil
}

// ── FullHunt ──────────────────────────────────────────────────────────────────

type FullHunt struct{}

func (s *FullHunt) Name() string   { return "fullhunt" }
func (s *FullHunt) NeedsKey() bool { return true }

func (s *FullHunt) Run(domain string, cfg map[string]string) <-chan models.Result {
	ch := make(chan models.Result, 200)
	go func() {
		defer close(ch)
		key := apiKey(cfg, "key")
		if key == "" {
			return
		}
		client := NewHTTPClient(30)
		url := fmt.Sprintf("https://fullhunt.io/api/v1/domain/%s/subdomains", domain)
		body, status, err := GET(client, url, map[string]string{"X-API-KEY": key})
		if err != nil || status != 200 {
			return
		}
		var resp struct {
			Hosts []string `json:"hosts"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			return
		}
		for _, h := range resp.Hosts {
			emit(ch, h, s.Name())
		}
	}()
	return ch
}

// ── Chaos (ProjectDiscovery) ──────────────────────────────────────────────────

type Chaos struct{}

func (s *Chaos) Name() string   { return "chaos" }
func (s *Chaos) NeedsKey() bool { return true }

func (s *Chaos) Run(domain string, cfg map[string]string) <-chan models.Result {
	ch := make(chan models.Result, 200)
	go func() {
		defer close(ch)
		key := apiKey(cfg, "key")
		if key == "" {
			return
		}
		client := NewHTTPClient(30)
		url := fmt.Sprintf("https://dns.projectdiscovery.io/dns/%s/subdomains", domain)
		body, status, err := GET(client, url, map[string]string{"Authorization": key})
		if err != nil || status != 200 {
			return
		}
		var resp struct {
			Subdomains []string `json:"subdomains"`
			Domain     string   `json:"domain"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			return
		}
		for _, sub := range resp.Subdomains {
			emit(ch, sub+"."+resp.Domain, s.Name())
		}
	}()
	return ch
}

// ── Netlas ────────────────────────────────────────────────────────────────────

type Netlas struct{}

func (s *Netlas) Name() string   { return "netlas" }
func (s *Netlas) NeedsKey() bool { return true }

func (s *Netlas) Run(domain string, cfg map[string]string) <-chan models.Result {
	ch := make(chan models.Result, 200)
	go func() {
		defer close(ch)
		key := apiKey(cfg, "key")
		if key == "" {
			return
		}
		client := NewHTTPClient(30)
		page := 0
		for {
			url := fmt.Sprintf(
				`https://app.netlas.io/api/domains/?q=domain:*.%s&source_type=include&start=%d&fields=domain`,
				domain, page*20,
			)
			body, status, err := GET(client, url, map[string]string{"X-API-Key": key})
			if err != nil || status != 200 {
				return
			}
			var resp struct {
				Items []struct {
					Data struct {
						Domain string `json:"domain"`
					} `json:"data"`
				} `json:"items"`
			}
			if err := json.Unmarshal(body, &resp); err != nil || len(resp.Items) == 0 {
				return
			}
			for _, item := range resp.Items {
				emit(ch, item.Data.Domain, s.Name())
			}
			if len(resp.Items) < 20 {
				return
			}
			page++
		}
	}()
	return ch
}

// ── LeakIX ────────────────────────────────────────────────────────────────────

type LeakIX struct{}

func (s *LeakIX) Name() string   { return "leakix" }
func (s *LeakIX) NeedsKey() bool { return false } // key optional, gives more results

func (s *LeakIX) Run(domain string, cfg map[string]string) <-chan models.Result {
	ch := make(chan models.Result, 200)
	go func() {
		defer close(ch)
		client := NewHTTPClient(30)
		headers := map[string]string{"Accept": "application/json"}
		if k := apiKey(cfg, "key"); k != "" {
			headers["api-key"] = k
		}
		page := 0
		for {
			url := fmt.Sprintf(
				"https://leakix.net/api/subdomains/%s?page=%d",
				domain, page,
			)
			body, status, err := GET(client, url, headers)
			if err != nil || status != 200 {
				return
			}
			var results []struct {
				Subdomain string `json:"subdomain"`
			}
			if err := json.Unmarshal(body, &results); err != nil || len(results) == 0 {
				return
			}
			for _, r := range results {
				emit(ch, r.Subdomain, s.Name())
			}
			if len(results) < 100 {
				return
			}
			page++
		}
	}()
	return ch
}

// ── PassiveTotal (RiskIQ) ─────────────────────────────────────────────────────

type PassiveTotal struct{}

func (s *PassiveTotal) Name() string   { return "passivetotal" }
func (s *PassiveTotal) NeedsKey() bool { return true }

func (s *PassiveTotal) Run(domain string, cfg map[string]string) <-chan models.Result {
	ch := make(chan models.Result, 200)
	go func() {
		defer close(ch)
		user := apiKey(cfg, "username")
		key := apiKey(cfg, "key")
		if user == "" || key == "" {
			return
		}
		client := NewHTTPClient(30)
		url := fmt.Sprintf(
			"https://api.passivetotal.org/v2/enrichment/subdomains?query=%s",
			domain,
		)
		req, err := newBasicAuthRequest(url, user, key)
		if err != nil {
			return
		}
		resp, err := client.Do(req)
		if err != nil {
			return
		}
		defer resp.Body.Close()
		var result struct {
			Subdomains []string `json:"subdomains"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return
		}
		for _, sub := range result.Subdomains {
			emit(ch, sub+"."+domain, s.Name())
		}
	}()
	return ch
}
