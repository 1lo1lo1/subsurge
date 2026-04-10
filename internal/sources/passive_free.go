package sources

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/user/subsurge/pkg/models"
)

// ── RapidDNS ─────────────────────────────────────────────────────────────────

type RapidDNS struct{}

func (s *RapidDNS) Name() string   { return "rapiddns" }
func (s *RapidDNS) NeedsKey() bool { return false }

var rapidRe = regexp.MustCompile(`<td><a[^>]*>([a-zA-Z0-9\.\-]+\.[a-zA-Z]{2,})<\/a><\/td>`)

func (s *RapidDNS) Run(domain string, cfg map[string]string) <-chan models.Result {
	ch := make(chan models.Result, 200)
	go func() {
		defer close(ch)
		client := NewHTTPClient(30)
		url := fmt.Sprintf("https://rapiddns.io/subdomain/%s?full=1", domain)
		body, status, err := GET(client, url, nil)
		if err != nil || status != 200 {
			return
		}
		matches := rapidRe.FindAllSubmatch(body, -1)
		for _, m := range matches {
			if len(m) > 1 {
				emit(ch, string(m[1]), s.Name())
			}
		}
	}()
	return ch
}

// ── BufferOver ────────────────────────────────────────────────────────────────

type BufferOver struct{}

func (s *BufferOver) Name() string   { return "bufferover" }
func (s *BufferOver) NeedsKey() bool { return false }

func (s *BufferOver) Run(domain string, cfg map[string]string) <-chan models.Result {
	ch := make(chan models.Result, 200)
	go func() {
		defer close(ch)
		client := NewHTTPClient(30)
		url := fmt.Sprintf("https://dns.bufferover.run/dns?q=.%s", domain)
		body, status, err := GET(client, url, nil)
		if err != nil || status != 200 {
			return
		}
		var resp struct {
			FDNS []string `json:"FDNS_A"`
			RDNS []string `json:"RDNS"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			return
		}
		for _, entry := range append(resp.FDNS, resp.RDNS...) {
			parts := strings.SplitN(entry, ",", 2)
			if len(parts) == 2 {
				emit(ch, parts[1], s.Name())
			}
		}
	}()
	return ch
}

// ── DNSRepo ───────────────────────────────────────────────────────────────────

type DNSRepo struct{}

func (s *DNSRepo) Name() string   { return "dnsrepo" }
func (s *DNSRepo) NeedsKey() bool { return false }

var dnsRepoRe = regexp.MustCompile(`([a-zA-Z0-9\-\.]+\.` + `[a-zA-Z]{2,})`)

func (s *DNSRepo) Run(domain string, cfg map[string]string) <-chan models.Result {
	ch := make(chan models.Result, 100)
	go func() {
		defer close(ch)
		client := NewHTTPClient(30)
		url := fmt.Sprintf("https://dnsrepo.noc.org/?domain=%s", domain)
		body, status, err := GET(client, url, nil)
		if err != nil || status != 200 {
			return
		}
		matches := dnsRepoRe.FindAllString(string(body), -1)
		suffix := "." + domain
		for _, m := range matches {
			if strings.HasSuffix(m, suffix) {
				emit(ch, m, s.Name())
			}
		}
	}()
	return ch
}
