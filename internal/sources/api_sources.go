package sources

import (
	"encoding/json"
	"fmt"

	"github.com/1lo1lo1/subsurge/pkg/models"
)

// ── VirusTotal ────────────────────────────────────────────────────────────────

type VirusTotal struct{}

func (s *VirusTotal) Name() string   { return "virustotal" }
func (s *VirusTotal) NeedsKey() bool { return true }

func (s *VirusTotal) Run(domain string, cfg map[string]string) <-chan models.Result {
	ch := make(chan models.Result, 200)
	go func() {
		defer close(ch)
		key := apiKey(cfg, "key")
		if key == "" {
			return
		}
		client := NewHTTPClient(30)
		cursor := ""
		for {
			url := fmt.Sprintf(
				"https://www.virustotal.com/api/v3/domains/%s/subdomains?limit=40&cursor=%s",
				domain, cursor,
			)
			body, status, err := GET(client, url, map[string]string{"x-apikey": key})
			if err != nil || status != 200 {
				return
			}
			var resp struct {
				Data []struct {
					ID string `json:"id"`
				} `json:"data"`
				Links struct {
					Next string `json:"next"`
				} `json:"links"`
				Meta struct {
					Cursor string `json:"cursor"`
				} `json:"meta"`
			}
			if err := json.Unmarshal(body, &resp); err != nil {
				return
			}
			for _, d := range resp.Data {
				emit(ch, d.ID, s.Name())
			}
			if resp.Meta.Cursor == "" || resp.Links.Next == "" {
				return
			}
			cursor = resp.Meta.Cursor
		}
	}()
	return ch
}

// ── SecurityTrails ────────────────────────────────────────────────────────────

type SecurityTrails struct{}

func (s *SecurityTrails) Name() string   { return "securitytrails" }
func (s *SecurityTrails) NeedsKey() bool { return true }

func (s *SecurityTrails) Run(domain string, cfg map[string]string) <-chan models.Result {
	ch := make(chan models.Result, 200)
	go func() {
		defer close(ch)
		key := apiKey(cfg, "key")
		if key == "" {
			return
		}
		client := NewHTTPClient(30)
		page := 1
		for {
			url := fmt.Sprintf(
				"https://api.securitytrails.com/v1/domain/%s/subdomains?children_only=false&include_inactive=true&page=%d",
				domain, page,
			)
			body, status, err := GET(client, url, map[string]string{
				"APIKEY":       key,
				"Content-Type": "application/json",
			})
			if err != nil || status != 200 {
				return
			}
			var resp struct {
				Subdomains []string `json:"subdomains"`
				Meta       struct {
					TotalPages int `json:"total_pages"`
				} `json:"meta"`
			}
			if err := json.Unmarshal(body, &resp); err != nil {
				return
			}
			for _, sub := range resp.Subdomains {
				emit(ch, sub+"."+domain, s.Name())
			}
			if page >= resp.Meta.TotalPages {
				return
			}
			page++
		}
	}()
	return ch
}

// ── Shodan ────────────────────────────────────────────────────────────────────

type Shodan struct{}

func (s *Shodan) Name() string   { return "shodan" }
func (s *Shodan) NeedsKey() bool { return true }

func (s *Shodan) Run(domain string, cfg map[string]string) <-chan models.Result {
	ch := make(chan models.Result, 200)
	go func() {
		defer close(ch)
		key := apiKey(cfg, "key")
		if key == "" {
			return
		}
		client := NewHTTPClient(30)
		url := fmt.Sprintf("https://api.shodan.io/dns/domain/%s?key=%s", domain, key)
		body, status, err := GET(client, url, nil)
		if err != nil || status != 200 {
			return
		}
		var resp struct {
			Subdomains []string `json:"subdomains"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			return
		}
		for _, sub := range resp.Subdomains {
			emit(ch, sub+"."+domain, s.Name())
		}
	}()
	return ch
}

// ── Censys ────────────────────────────────────────────────────────────────────

type Censys struct{}

func (s *Censys) Name() string   { return "censys" }
func (s *Censys) NeedsKey() bool { return true }

func (s *Censys) Run(domain string, cfg map[string]string) <-chan models.Result {
	ch := make(chan models.Result, 200)
	go func() {
		defer close(ch)
		id := apiKey(cfg, "api_id")
		secret := apiKey(cfg, "api_secret")
		if id == "" || secret == "" {
			return
		}
		client := NewHTTPClient(30)
		page := 1
		for {
			url := fmt.Sprintf(
				`https://search.censys.io/api/v2/certificates/search?q=parsed.names: %s&per_page=100&page=%d`,
				domain, page,
			)
			req, _ := newBasicAuthRequest(url, id, secret)
			if req == nil {
				return
			}
			resp, err := client.Do(req)
			if err != nil {
				return
			}
			var result struct {
				Result struct {
					Hits []struct {
						ParsedNames []string `json:"parsed.names"`
					} `json:"hits"`
					Total int `json:"total"`
				} `json:"result"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
				resp.Body.Close()
				return
			}
			resp.Body.Close()
			for _, hit := range result.Result.Hits {
				for _, name := range hit.ParsedNames {
					emit(ch, name, s.Name())
				}
			}
			if len(result.Result.Hits) < 100 {
				return
			}
			page++
			if page > 10 { // cap to avoid very long runs
				return
			}
		}
	}()
	return ch
}

// ── BinaryEdge ────────────────────────────────────────────────────────────────

type BinaryEdge struct{}

func (s *BinaryEdge) Name() string   { return "binaryedge" }
func (s *BinaryEdge) NeedsKey() bool { return true }

func (s *BinaryEdge) Run(domain string, cfg map[string]string) <-chan models.Result {
	ch := make(chan models.Result, 200)
	go func() {
		defer close(ch)
		key := apiKey(cfg, "key")
		if key == "" {
			return
		}
		client := NewHTTPClient(30)
		page := 1
		for {
			url := fmt.Sprintf(
				"https://api.binaryedge.io/v2/query/domains/subdomain/%s?page=%d",
				domain, page,
			)
			body, status, err := GET(client, url, map[string]string{"X-Key": key})
			if err != nil || status != 200 {
				return
			}
			var resp struct {
				Events  []string `json:"events"`
				Page    int      `json:"page"`
				Total   int      `json:"total"`
				PageSize int     `json:"pagesize"`
			}
			if err := json.Unmarshal(body, &resp); err != nil {
				return
			}
			for _, sub := range resp.Events {
				emit(ch, sub, s.Name())
			}
			if resp.Page*resp.PageSize >= resp.Total {
				return
			}
			page++
		}
	}()
	return ch
}
