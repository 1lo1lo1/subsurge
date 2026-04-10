package filter_test

import (
	"testing"

	"github.com/user/subsurge/internal/filter"
	"github.com/user/subsurge/pkg/models"
)

func newResult(domain string) *models.Result {
	return &models.Result{Domain: domain, Source: "test"}
}

func TestAllow_ValidSubdomains(t *testing.T) {
	eng, _ := filter.New(false, "", "")
	valid := []string{
		"www.example.com",
		"api.example.com",
		"staging-01.api.example.com",
		"mail.example.co.uk",
		"xn--p1ai.example.com", // punycode label
	}
	for _, d := range valid {
		if !eng.Allow(newResult(d)) {
			t.Errorf("expected Allow(%q) = true", d)
		}
	}
}

func TestAllow_InvalidSubdomains(t *testing.T) {
	eng, _ := filter.New(false, "", "")
	invalid := []string{
		"",
		"*.example.com",
		"*example.com",
		"-.example.com",
		"example.com.",         // trailing dot (should be stripped and re-checked)
		"a..b.example.com",    // empty label
		"<script>.example.com",
	}
	for _, d := range invalid {
		r := newResult(d)
		got := eng.Allow(r)
		// Trailing dot should be stripped and allowed if otherwise valid
		if d == "example.com." {
			continue // strip logic handles this
		}
		if got {
			t.Errorf("expected Allow(%q) = false, got true", d)
		}
	}
}

func TestAllow_Deduplication(t *testing.T) {
	eng, _ := filter.New(false, "", "")
	r := newResult("sub.example.com")
	if !eng.Allow(r) {
		t.Fatal("first occurrence should be allowed")
	}
	// Second occurrence of the same domain
	r2 := newResult("sub.example.com")
	if eng.Allow(r2) {
		t.Fatal("duplicate should be rejected")
	}
}

func TestAllow_MatchRegex(t *testing.T) {
	eng, _ := filter.New(false, `^(api|staging)\.`, "")
	cases := []struct {
		domain string
		want   bool
	}{
		{"api.example.com", true},
		{"staging.example.com", true},
		{"www.example.com", false},
		{"mail.example.com", false},
	}
	for _, c := range cases {
		got := eng.Allow(newResult(c.domain))
		if got != c.want {
			t.Errorf("Allow(%q) = %v, want %v", c.domain, got, c.want)
		}
	}
}

func TestAllow_SkipRegex(t *testing.T) {
	eng, _ := filter.New(false, "", `^mail\.`)
	cases := []struct {
		domain string
		want   bool
	}{
		{"api.example.com", true},
		{"mail.example.com", false},
		{"mail.sub.example.com", false},
	}
	for _, c := range cases {
		got := eng.Allow(newResult(c.domain))
		if got != c.want {
			t.Errorf("Allow(%q) = %v, want %v", c.domain, got, c.want)
		}
	}
}

func TestAllow_TrailingDotStripped(t *testing.T) {
	eng, _ := filter.New(false, "", "")
	r := newResult("www.example.com.")
	if !eng.Allow(r) {
		t.Error("trailing dot should be stripped and result allowed")
	}
	if r.Domain != "www.example.com" {
		t.Errorf("domain should have trailing dot removed, got %q", r.Domain)
	}
}

func TestAllow_WildcardPrefixes(t *testing.T) {
	eng, _ := filter.New(false, "", "")
	wildcards := []string{
		"*.example.com",
		"*example.com",
	}
	for _, w := range wildcards {
		if eng.Allow(newResult(w)) {
			t.Errorf("wildcard %q should be rejected", w)
		}
	}
}

func BenchmarkAllow(b *testing.B) {
	eng, _ := filter.New(false, "", "")
	domains := []string{
		"api.example.com",
		"staging.example.com",
		"www.example.com",
		"mail.example.com",
		"cdn.example.com",
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		eng.Allow(newResult(domains[i%len(domains)]))
	}
}
