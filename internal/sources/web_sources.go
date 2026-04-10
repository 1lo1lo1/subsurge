package sources

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/1lo1lo1/subsurge/pkg/models"
)

// ── GitHub ────────────────────────────────────────────────────────────────────

type GitHub struct{}

func (s *GitHub) Name() string   { return "github" }
func (s *GitHub) NeedsKey() bool { return true }

func (s *GitHub) Run(domain string, cfg map[string]string) <-chan models.Result {
	ch := make(chan models.Result, 200)
	go func() {
		defer close(ch)
		token := apiKey(cfg, "token")
		if token == "" {
			return
		}
		client := NewHTTPClient(30)
		headers := map[string]string{
			"Authorization": "token " + token,
			"Accept":        "application/vnd.github.v3.text-match+json",
		}
		queries := []string{
			fmt.Sprintf("%q in:file extension:txt", domain),
			fmt.Sprintf("%q in:file extension:yaml", domain),
			fmt.Sprintf("%q in:file extension:json", domain),
			fmt.Sprintf("%q in:file extension:env", domain),
		}
		domainRe := regexp.MustCompile(
			`[a-zA-Z0-9\-\.]+\.` + regexp.QuoteMeta(domain),
		)
		seen := make(map[string]struct{})

		for _, q := range queries {
			url := fmt.Sprintf(
				"https://api.github.com/search/code?q=%s&per_page=100", q,
			)
			body, status, err := GET(client, url, headers)
			if err != nil || status != 200 {
				continue
			}
			var resp struct {
				Items []struct {
					TextMatches []struct {
						Fragment string `json:"fragment"`
					} `json:"text_matches"`
				} `json:"items"`
			}
			if err := json.Unmarshal(body, &resp); err != nil {
				continue
			}
			for _, item := range resp.Items {
				for _, tm := range item.TextMatches {
					for _, m := range domainRe.FindAllString(tm.Fragment, -1) {
						m = strings.ToLower(m)
						if _, ok := seen[m]; !ok {
							seen[m] = struct{}{}
							emit(ch, m, s.Name())
						}
					}
				}
			}
		}
	}()
	return ch
}

// ── Wayback Machine ───────────────────────────────────────────────────────────

type Wayback struct{}

func (s *Wayback) Name() string   { return "wayback" }
func (s *Wayback) NeedsKey() bool { return false }

func (s *Wayback) Run(domain string, cfg map[string]string) <-chan models.Result {
	ch := make(chan models.Result, 200)
	go func() {
		defer close(ch)
		client := NewHTTPClient(60)
		url := fmt.Sprintf(
			"http://web.archive.org/cdx/search/cdx?url=*.%s&output=text&fl=original&collapse=urlkey&limit=100000",
			domain,
		)
		body, status, err := GET(client, url, nil)
		if err != nil || status != 200 {
			return
		}
		domainRe := regexp.MustCompile(
			`(?:https?://)?([a-zA-Z0-9\-\.]+\.` + regexp.QuoteMeta(domain) + `)`,
		)
		seen := make(map[string]struct{})
		scanner := bufio.NewScanner(bytes.NewReader(body))
		for scanner.Scan() {
			if m := domainRe.FindStringSubmatch(scanner.Text()); len(m) > 1 {
				sub := strings.ToLower(m[1])
				if _, ok := seen[sub]; !ok {
					seen[sub] = struct{}{}
					emit(ch, sub, s.Name())
				}
			}
		}
	}()
	return ch
}

// ── CommonCrawl ───────────────────────────────────────────────────────────────

type CommonCrawl struct{}

func (s *CommonCrawl) Name() string   { return "commoncrawl" }
func (s *CommonCrawl) NeedsKey() bool { return false }

func (s *CommonCrawl) Run(domain string, cfg map[string]string) <-chan models.Result {
	ch := make(chan models.Result, 200)
	go func() {
		defer close(ch)
		client := NewHTTPClient(60)
		body, status, err := GET(client, "https://index.commoncrawl.org/collinfo.json", nil)
		if err != nil || status != 200 {
			return
		}
		var indexes []struct {
			CDXAPI string `json:"cdx-api"`
		}
		if err := json.Unmarshal(body, &indexes); err != nil || len(indexes) == 0 {
			return
		}
		if len(indexes) > 3 {
			indexes = indexes[:3]
		}
		domainRe := regexp.MustCompile(
			`([a-zA-Z0-9\-\.]+\.` + regexp.QuoteMeta(domain) + `)`,
		)
		seen := make(map[string]struct{})
		for _, idx := range indexes {
			url := fmt.Sprintf("%s?url=*.%s&output=text&fl=url&limit=50000", idx.CDXAPI, domain)
			body, status, err := GET(client, url, nil)
			if err != nil || status != 200 {
				continue
			}
			scanner := bufio.NewScanner(bytes.NewReader(body))
			for scanner.Scan() {
				if m := domainRe.FindString(scanner.Text()); m != "" {
					m = strings.ToLower(m)
					if _, ok := seen[m]; !ok {
						seen[m] = struct{}{}
						emit(ch, m, s.Name())
					}
				}
			}
		}
	}()
	return ch
}

// ── DNSDumpster ───────────────────────────────────────────────────────────────

type DNSDumpster struct{}

func (s *DNSDumpster) Name() string   { return "dnsdumpster" }
func (s *DNSDumpster) NeedsKey() bool { return false }

func (s *DNSDumpster) Run(domain string, cfg map[string]string) <-chan models.Result {
	ch := make(chan models.Result, 200)
	go func() {
		defer close(ch)
		client := NewHTTPClient(30)

		// Step 1: grab CSRF token
		homePage, status, err := GET(client, "https://dnsdumpster.com", nil)
		if err != nil || status != 200 {
			return
		}
		csrfRe := regexp.MustCompile(`csrfmiddlewaretoken.*?value=['"](.*?)['"]`)
		m := csrfRe.FindSubmatch(homePage)
		if len(m) < 2 {
			return
		}
		csrfToken := string(m[1])

		// Step 2: POST with domain
		postBody := fmt.Sprintf("csrfmiddlewaretoken=%s&targetip=%s&user=free", csrfToken, domain)
		req, err := http.NewRequestWithContext(
			context.Background(), http.MethodPost,
			"https://dnsdumpster.com",
			strings.NewReader(postBody),
		)
		if err != nil {
			return
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Referer", "https://dnsdumpster.com")
		req.Header.Set("Cookie", "csrftoken="+csrfToken)
		req.Header.Set("User-Agent", "Mozilla/5.0 subsurge/1.0")

		resp, err := client.Do(req)
		if err != nil {
			return
		}
		defer resp.Body.Close()

		respBody, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
		if err != nil {
			return
		}

		subRe := regexp.MustCompile(
			`([a-zA-Z0-9\-\.]+\.` + regexp.QuoteMeta(domain) + `)`,
		)
		seen := make(map[string]struct{})
		for _, match := range subRe.FindAllString(string(respBody), -1) {
			match = strings.ToLower(match)
			if _, ok := seen[match]; !ok {
				seen[match] = struct{}{}
				emit(ch, match, s.Name())
			}
		}
	}()
	return ch
}

// ── Sublist3r API ─────────────────────────────────────────────────────────────

type Sublist3r struct{}

func (s *Sublist3r) Name() string   { return "sublist3r" }
func (s *Sublist3r) NeedsKey() bool { return false }

func (s *Sublist3r) Run(domain string, cfg map[string]string) <-chan models.Result {
	ch := make(chan models.Result, 200)
	go func() {
		defer close(ch)
		client := NewHTTPClient(30)
		url := fmt.Sprintf("https://api.sublist3r.com/search.php?domain=%s", domain)
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

// ── Hunter.io ─────────────────────────────────────────────────────────────────

type Hunter struct{}

func (s *Hunter) Name() string   { return "hunter" }
func (s *Hunter) NeedsKey() bool { return true }

func (s *Hunter) Run(domain string, cfg map[string]string) <-chan models.Result {
	ch := make(chan models.Result, 100)
	go func() {
		defer close(ch)
		key := apiKey(cfg, "key")
		if key == "" {
			return
		}
		client := NewHTTPClient(30)
		url := fmt.Sprintf(
			"https://api.hunter.io/v2/domain-search?domain=%s&api_key=%s&limit=100",
			domain, key,
		)
		body, status, err := GET(client, url, nil)
		if err != nil || status != 200 {
			return
		}
		var resp struct {
			Data struct {
				Domain  string `json:"domain"`
				Emails  []struct {
					Value string `json:"value"`
				} `json:"emails"`
			} `json:"data"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			return
		}
		// Hunter doesn't give subdomains directly but email addresses can reveal them
		subRe := regexp.MustCompile(`@([a-zA-Z0-9\-\.]+\.` + regexp.QuoteMeta(domain) + `)`)
		for _, email := range resp.Data.Emails {
			if m := subRe.FindStringSubmatch(email.Value); len(m) > 1 {
				emit(ch, m[1], s.Name())
			}
		}
	}()
	return ch
}

// ── Shodan InternetDB (free, no key) ─────────────────────────────────────────

type ShodanInternetDB struct{}

func (s *ShodanInternetDB) Name() string   { return "shodaninternetdb" }
func (s *ShodanInternetDB) NeedsKey() bool { return false }

func (s *ShodanInternetDB) Run(domain string, cfg map[string]string) <-chan models.Result {
	ch := make(chan models.Result, 100)
	go func() {
		defer close(ch)
		// InternetDB works on IPs, not domains; use crt.sh resolved IPs as input
		// This source piggybacks off crt.sh results resolved live — skip if no IPs
		// Real implementation would resolve the domain first, then query IPs
		// For safety, this source is a no-op unless combined with an active resolver
	}()
	return ch
}
