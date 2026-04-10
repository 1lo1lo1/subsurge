package sources

import (
	"fmt"
	"strings"

	"github.com/1lo1lo1/subsurge/pkg/models"
)

type HackerTarget struct{}

func (s *HackerTarget) Name() string   { return "hackertarget" }
func (s *HackerTarget) NeedsKey() bool { return false }

func (s *HackerTarget) Run(domain string, cfg map[string]string) <-chan models.Result {
	ch := make(chan models.Result, 200)
	go func() {
		defer close(ch)
		client := NewHTTPClient(30)
		url := fmt.Sprintf("https://api.hackertarget.com/hostsearch/?q=%s", domain)
		body, status, err := GET(client, url, nil)
		if err != nil || status != 200 {
			return
		}
		text := string(body)
		if strings.Contains(text, "API count exceeded") || strings.Contains(text, "error") {
			return
		}
		for _, line := range strings.Split(text, "\n") {
			parts := strings.SplitN(line, ",", 2)
			if len(parts) > 0 {
				emit(ch, parts[0], s.Name())
			}
		}
	}()
	return ch
}
