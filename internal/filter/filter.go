package filter

import (
	"net"
	"regexp"
	"strings"
	"sync"

	"github.com/1lo1lo1/subsurge/pkg/models"
)

var (
	// validSubdomain matches sane subdomain labels.
	validLabel = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$`)

	// wildcardPrefixes are patterns that indicate a wildcard result.
	wildcardPrefixes = []string{"*.", "*"}
)

// Engine deduplicates, validates and optionally wildcard-filters results.
type Engine struct {
	mu      sync.Mutex
	seen    map[string]struct{}
	rootIP  map[string]string // domain -> IP of wildcard resolution
	noWild  bool
	matchRe *regexp.Regexp
	skipRe  *regexp.Regexp
}

// New creates a new filter Engine.
// noWildcard: drop results that resolve to the same IP as the bare domain.
// matchPattern / skipPattern: optional regex filters on the subdomain string.
func New(noWildcard bool, matchPattern, skipPattern string) (*Engine, error) {
	e := &Engine{
		seen:   make(map[string]struct{}),
		rootIP: make(map[string]string),
		noWild: noWildcard,
	}
	var err error
	if matchPattern != "" {
		e.matchRe, err = regexp.Compile(matchPattern)
		if err != nil {
			return nil, err
		}
	}
	if skipPattern != "" {
		e.skipRe, err = regexp.Compile(skipPattern)
		if err != nil {
			return nil, err
		}
	}
	return e, nil
}

// Allow returns true if the result should be kept.
func (e *Engine) Allow(r *models.Result) bool {
	domain := strings.ToLower(strings.TrimSpace(r.Domain))
	if domain == "" {
		return false
	}

	// Strip trailing dot (from DNS responses)
	domain = strings.TrimSuffix(domain, ".")
	r.Domain = domain

	// Reject wildcard indicators
	for _, p := range wildcardPrefixes {
		if strings.HasPrefix(domain, p) {
			return false
		}
	}

	// Validate each label
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return false
	}
	for _, label := range parts {
		if !validLabel.MatchString(label) {
			return false
		}
	}

	// Apply match/skip regex filters
	if e.matchRe != nil && !e.matchRe.MatchString(domain) {
		return false
	}
	if e.skipRe != nil && e.skipRe.MatchString(domain) {
		return false
	}

	// Deduplication
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, exists := e.seen[domain]; exists {
		return false
	}
	e.seen[domain] = struct{}{}
	return true
}

// IsWildcard checks whether a domain resolves to the same IP as the parent
// wildcard record (rand123.<domain>). Returns true = wildcard hit.
func IsWildcard(domain string) bool {
	// Resolve a random prefix that almost certainly doesn't exist legitimately.
	probe := "subsurge-probe-xzqw9." + domain
	ips, err := net.LookupHost(probe)
	if err != nil || len(ips) == 0 {
		return false
	}
	return true
}

// WildcardIP resolves the wildcard IP for a root domain.
func WildcardIP(domain string) string {
	probe := "subsurge-probe-xzqw9." + domain
	ips, err := net.LookupHost(probe)
	if err != nil || len(ips) == 0 {
		return ""
	}
	return ips[0]
}
