package sources

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/1lo1lo1/subsurge/pkg/models"
)

type CrtSh struct{}

func (s *CrtSh) Name() string     { return "crtsh" }
func (s *CrtSh) NeedsKey() bool   { return false }

func (s *CrtSh) Run(domain string, cfg map[string]string) <-chan models.Result {
	ch := make(chan models.Result, 200)
	go func() {
		defer close(ch)
		client := NewHTTPClient(30)
		url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)
		body, status, err := GET(client, url, nil)
		if err != nil || status != 200 {
			return
		}
		var entries []struct {
			NameValue string `json:"name_value"`
		}
		if err := json.Unmarshal(body, &entries); err != nil {
			return
		}
		for _, e := range entries {
			// name_value can contain multiple newline-separated names
			for _, name := range strings.Split(e.NameValue, "\n") {
				name = strings.TrimSpace(strings.ToLower(name))
				if strings.HasSuffix(name, "."+domain) || name == domain {
					emit(ch, name, s.Name())
				}
			}
		}
	}()
	return ch
}
