package sources

import (
	"sort"

	"github.com/1lo1lo1/subsurge/pkg/models"
)

// All returns every registered source, keyed by name.
func All() map[string]models.Source {
	return map[string]models.Source{
		// ── Free / no key required ──────────────────────────────────────────
		"crtsh":           &CrtSh{},
		"certspotter":     &Certspotter{},
		"hackertarget":    &HackerTarget{},
		"threatcrowd":     &ThreatCrowd{},
		"rapiddns":        &RapidDNS{},
		"bufferover":      &BufferOver{},
		"dnsrepo":         &DNSRepo{},
		"alienvault":      &AlienVault{},
		"urlscan":         &URLScan{},
		"threatminer":     &ThreatMiner{},
		"anubis":          &Anubis{},
		"wayback":         &Wayback{},
		"commoncrawl":     &CommonCrawl{},
		"dnsdumpster":     &DNSDumpster{},
		"sublist3r":       &Sublist3r{},
		"leakix":          &LeakIX{}, // free tier exists

		// ── Require API key ─────────────────────────────────────────────────
		"virustotal":      &VirusTotal{},
		"securitytrails":  &SecurityTrails{},
		"shodan":          &Shodan{},
		"censys":          &Censys{},
		"binaryedge":      &BinaryEdge{},
		"fullhunt":        &FullHunt{},
		"chaos":           &Chaos{},
		"netlas":          &Netlas{},
		"passivetotal":    &PassiveTotal{},
		"hunter":          &Hunter{},
		"github":          &GitHub{},
	}
}

// Names returns a sorted list of all source names.
func Names() []string {
	m := All()
	names := make([]string, 0, len(m))
	for k := range m {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}

// Select returns only the sources matching the include/exclude lists.
// If include is empty, all sources are included. Exclude always wins.
// If keyOnly is true, only sources that require an API key are included.
// If freeOnly is true, only sources that don't require a key are included.
func Select(include, exclude []string, freeOnly, keyOnly bool) []models.Source {
	all := All()

	includeSet := make(map[string]struct{}, len(include))
	for _, s := range include {
		includeSet[s] = struct{}{}
	}
	excludeSet := make(map[string]struct{}, len(exclude))
	for _, s := range exclude {
		excludeSet[s] = struct{}{}
	}

	var result []models.Source
	for name, src := range all {
		if _, skip := excludeSet[name]; skip {
			continue
		}
		if len(includeSet) > 0 {
			if _, ok := includeSet[name]; !ok {
				continue
			}
		}
		if freeOnly && src.NeedsKey() {
			continue
		}
		if keyOnly && !src.NeedsKey() {
			continue
		}
		result = append(result, src)
	}

	// Sort for deterministic order
	sort.Slice(result, func(i, j int) bool {
		return result[i].Name() < result[j].Name()
	})
	return result
}
