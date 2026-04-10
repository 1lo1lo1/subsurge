package models

import "time"

// Result represents a discovered subdomain with metadata.
type Result struct {
	Domain    string    `json:"domain"`
	Source    string    `json:"source"`
	Timestamp time.Time `json:"timestamp"`
	IP        string    `json:"ip,omitempty"`
}

// Source is the interface every data source must implement.
type Source interface {
	// Name returns the unique identifier of this source (e.g. "crtsh").
	Name() string
	// Run queries the source for subdomains of the given domain and sends
	// results on the returned channel. It closes the channel when done.
	Run(domain string, cfg map[string]string) <-chan Result
	// NeedsKey reports whether this source requires an API key to operate.
	NeedsKey() bool
}

// Stats holds per-run statistics.
type Stats struct {
	Total      int
	Unique     int
	BySource   map[string]int
	Filtered   int
	Duration   time.Duration
}
