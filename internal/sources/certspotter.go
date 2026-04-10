package sources

import (
	"encoding/json"
	"fmt"

	"github.com/user/subsurge/pkg/models"
)

type Certspotter struct{}

func (s *Certspotter) Name() string   { return "certspotter" }
func (s *Certspotter) NeedsKey() bool { return false }

func (s *Certspotter) Run(domain string, cfg map[string]string) <-chan models.Result {
	ch := make(chan models.Result, 200)
	go func() {
		defer close(ch)
		client := NewHTTPClient(30)
		// Paginate through all results
		after := ""
		for {
			url := fmt.Sprintf(
				"https://api.certspotter.com/v1/issuances?domain=%s&include_subdomains=true&expand=dns_names&after=%s",
				domain, after,
			)
			body, status, err := GET(client, url, nil)
			if err != nil || status != 200 {
				return
			}
			var entries []struct {
				ID       string   `json:"id"`
				DNSNames []string `json:"dns_names"`
			}
			if err := json.Unmarshal(body, &entries); err != nil || len(entries) == 0 {
				return
			}
			for _, e := range entries {
				for _, name := range e.DNSNames {
					emit(ch, name, s.Name())
				}
				after = e.ID
			}
			if len(entries) < 100 {
				return
			}
		}
	}()
	return ch
}
