package sources

import (
	"encoding/json"
	"fmt"

	"github.com/user/subsurge/pkg/models"
)

type ThreatCrowd struct{}

func (s *ThreatCrowd) Name() string   { return "threatcrowd" }
func (s *ThreatCrowd) NeedsKey() bool { return false }

func (s *ThreatCrowd) Run(domain string, cfg map[string]string) <-chan models.Result {
	ch := make(chan models.Result, 100)
	go func() {
		defer close(ch)
		client := NewHTTPClient(30)
		url := fmt.Sprintf("https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=%s", domain)
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
			emit(ch, sub, s.Name())
		}
	}()
	return ch
}
