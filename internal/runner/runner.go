package runner

import (
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/user/subsurge/internal/config"
	"github.com/user/subsurge/internal/filter"
	"github.com/user/subsurge/internal/output"
	"github.com/user/subsurge/internal/ratelimit"
	"github.com/user/subsurge/internal/sources"
	"github.com/user/subsurge/pkg/models"
)

// Options controls a single enumeration run.
type Options struct {
	Domains      []string
	Include      []string
	Exclude      []string
	FreeOnly     bool
	KeyOnly      bool
	NoWildcard   bool
	MatchPattern string
	SkipPattern  string
	Format       output.Format
	OutputFile   string
	NoColor      bool
	Silent       bool
	Verbose      bool
	ConfigPath   string
	Timeout      int
}

// Run executes subdomain enumeration for all configured domains.
func Run(opts *Options) error {
	// Load config
	cfg, err := config.Load(opts.ConfigPath)
	if err != nil {
		return err
	}
	if opts.Timeout > 0 {
		cfg.Timeout = opts.Timeout
	}

	// Build output writer
	w, err := output.New(opts.Format, opts.OutputFile, opts.NoColor, opts.Silent, opts.Verbose)
	if err != nil {
		return err
	}
	w.Banner()

	// Build filter
	eng, err := filter.New(opts.NoWildcard, opts.MatchPattern, opts.SkipPattern)
	if err != nil {
		return err
	}

	// Select sources
	srcs := sources.Select(opts.Include, opts.Exclude, opts.FreeOnly, opts.KeyOnly)
	if len(srcs) == 0 {
		w.Error("No sources selected")
		return nil
	}

	// Process each domain
	for _, domain := range opts.Domains {
		domain = strings.ToLower(strings.TrimSpace(domain))
		if domain == "" {
			continue
		}
		if err := runDomain(domain, srcs, cfg, eng, w, opts); err != nil {
			w.Error("Domain %s: %v", domain, err)
		}
	}

	return nil
}

func runDomain(
	domain string,
	srcs []models.Source,
	cfg *config.Config,
	eng *filter.Engine,
	w *output.Writer,
	opts *Options,
) error {
	start := time.Now()

	w.Info("Enumerating subdomains for [%s] using %d sources", domain, len(srcs))

	// Check for wildcard DNS
	if opts.NoWildcard {
		if wip := filter.WildcardIP(domain); wip != "" {
			w.Warn("Wildcard DNS detected for %s (resolves to %s) — wildcard filtering enabled", domain, wip)
		}
	}

	var (
		total    int64
		filtered int64
		bySource = make(map[string]*int64)
		bsMu     sync.Mutex
	)

	// Fan-out: launch all sources concurrently
	var wg sync.WaitGroup
	results := make(chan models.Result, 500)

	for _, src := range srcs {
		src := src // capture
		srcCfg := cfg.Keys[src.Name()]
		if srcCfg == nil {
			srcCfg = map[string]string{}
		}

		// Build rate limiter for this source
		var rl *ratelimit.Limiter
		if rps, ok := cfg.RateLimit[src.Name()]; ok {
			rl = ratelimit.New(rps)
		} else {
			rl = ratelimit.New(0) // unlimited
		}

		wg.Add(1)
		go func(s models.Source, scfg map[string]string, limiter *ratelimit.Limiter) {
			defer wg.Done()

			if s.NeedsKey() {
				if _, hasKey := scfg["key"]; !hasKey {
					if _, hasID := scfg["api_id"]; !hasID {
						if _, hasToken := scfg["token"]; !hasToken {
							if _, hasUser := scfg["username"]; !hasUser {
								w.Verbose("Skipping %s (no API key configured)", s.Name())
								return
							}
						}
					}
				}
			}

			w.Verbose("Starting source: %s", s.Name())
			ch := s.Run(domain, scfg)

			var count int64
			for r := range ch {
				limiter.Wait()
				results <- r
				atomic.AddInt64(&count, 1)
			}

			w.Verbose("Source %s finished: %d results", s.Name(), count)
			bsMu.Lock()
			v := count
			bySource[s.Name()] = &v
			bsMu.Unlock()
		}(src, srcCfg, rl)
	}

	// Close results channel when all sources finish
	go func() {
		wg.Wait()
		close(results)
	}()

	// Fan-in: consume results
	for r := range results {
		atomic.AddInt64(&total, 1)
		rCopy := r
		if eng.Allow(&rCopy) {
			w.Write(&rCopy)
		} else {
			atomic.AddInt64(&filtered, 1)
		}
	}

	// Compute unique count
	bsMu.Lock()
	srcMap := make(map[string]int, len(bySource))
	for k, v := range bySource {
		srcMap[k] = int(*v)
	}
	bsMu.Unlock()

	unique := int(total) - int(filtered)
	stats := &models.Stats{
		Total:    int(total),
		Unique:   unique,
		BySource: srcMap,
		Filtered: int(filtered),
		Duration: time.Since(start),
	}

	return w.Flush(stats)
}
