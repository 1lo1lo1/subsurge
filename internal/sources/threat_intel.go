package sources

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/user/subsurge/pkg/models"
)

// ── AlienVault OTX ───────────────────────────────────────────────────────────

type AlienVault struct{}

func (s *AlienVault) Name() string   { return "alienvault" }
func (s *AlienVault) NeedsKey() bool { return false }

func (s *AlienVault) Run(domain string, cfg map[string]string) <-chan models.Result {
	ch := make(chan models.Result, 200)
	go func() {
		defer close(ch)
		client := NewHTTPClient(30)
		page := 1
		for {
			url := fmt.Sprintf(
				"https://otx.alienvault.com/api/v1/indicators/domain/%s/passive_dns?limit=500&page=%d",
				domain, page,
			)
			body, status, err := GET(client, url, nil)
			if err != nil || status != 200 {
				return
			}
			var resp struct {
				PassiveDNS []struct {
					Hostname string `json:"hostname"`
				} `json:"passive_dns"`
				HasNext bool `json:"has_next"`
			}
			if err := json.Unmarshal(body, &resp); err != nil {
				return
			}
			for _, r := range resp.PassiveDNS {
				emit(ch, r.Hostname, s.Name())
			}
			if !resp.HasNext {
				return
			}
			page++
		}
	}()
	return ch
}

// ── URLScan ───────────────────────────────────────────────────────────────────

type URLScan struct{}

func (s *URLScan) Name() string   { return "urlscan" }
func (s *URLScan) NeedsKey() bool { return false }

func (s *URLScan) Run(domain string, cfg map[string]string) <-chan models.Result {
	ch := make(chan models.Result, 200)
	go func() {
		defer close(ch)
		client := NewHTTPClient(30)
		headers := map[string]string{}
		if k := apiKey(cfg, "key"); k != "" {
			headers["API-Key"] = k
		}
		url := fmt.Sprintf(
			"https://urlscan.io/api/v1/search/?q=domain:%s&size=10000&fields=page.domain",
			domain,
		)
		body, status, err := GET(client, url, headers)
		if err != nil || status != 200 {
			return
		}
		var resp struct {
			Results []struct {
				Page struct {
					Domain string `json:"domain"`
				} `json:"page"`
			} `json:"results"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			return
		}
		for _, r := range resp.Results {
			if strings.HasSuffix(r.Page.Domain, "."+domain) || r.Page.Domain == domain {
				emit(ch, r.Page.Domain, s.Name())
			}
		}
	}()
	return ch
}

// ── ThreatMiner ───────────────────────────────────────────────────────────────

type ThreatMiner struct{}

func (s *ThreatMiner) Name() string   { return "threatminer" }
func (s *ThreatMiner) NeedsKey() bool { return false }

func (s *ThreatMiner) Run(domain string, cfg map[string]string) <-chan models.Result {
	ch := make(chan models.Result, 100)
	go func() {
		defer close(ch)
		client := NewHTTPClient(30)
		url := fmt.Sprintf("https://api.threatminer.org/v2/domain.php?q=%s&rt=5", domain)
		body, status, err := GET(client, url, nil)
		if err != nil || status != 200 {
			return
		}
		var resp struct {
			Results []string `json:"results"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			return
		}
		for _, sub := range resp.Results {
			emit(ch, sub, s.Name())
		}
	}()
	return ch
}

// ── Anubis ────────────────────────────────────────────────────────────────────

type Anubis struct{}

func (s *Anubis) Name() string   { return "anubis" }
func (s *Anubis) NeedsKey() bool { return false }

func (s *Anubis) Run(domain string, cfg map[string]string) <-chan models.Result {
	ch := make(chan models.Result, 200)
	go func() {
		defer close(ch)
		client := NewHTTPClient(30)
		url := fmt.Sprintf("https://jonlu.ca/anubis/subdomains/%s", domain)
		body, status, err := GET(client, url, nil)
		if err != nil || status != 200 {
			return
		}
		var subdomains []string
		if err := json.Unmarshal(body, &subdomains); err != nil {
			return
		}
		for _, sub := range subdomains {
			emit(ch, sub, s.Name())
		}
	}()
	return ch
}
