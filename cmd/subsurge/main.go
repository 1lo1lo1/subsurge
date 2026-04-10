package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/1lo1lo1/subsurge/internal/config"
	"github.com/1lo1lo1/subsurge/internal/output"
	"github.com/1lo1lo1/subsurge/internal/runner"
	"github.com/1lo1lo1/subsurge/internal/sources"
)

var version = "1.0.0"

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// ── flags ─────────────────────────────────────────────────────────────────────

var (
	flagDomain       string
	flagList         string
	flagOutput       string
	flagFormat       string
	flagSources      []string
	flagExclude      []string
	flagFreeOnly     bool
	flagKeyOnly      bool
	flagNoWildcard   bool
	flagMatchPattern string
	flagSkipPattern  string
	flagSilent       bool
	flagVerbose      bool
	flagNoColor      bool
	flagTimeout      int
	flagConfigPath   string
)

// ── root command ──────────────────────────────────────────────────────────────

var rootCmd = &cobra.Command{
	Use:   "subsurge",
	Short: "Fast passive subdomain enumeration engine",
	Long: color.CyanString(`
  ____        _   ____
 / ___| _   _| |_/ ___| _   _ _ __ __ _  ___
 \___ \| | | | '_ \___ \| | | | '__/ _`) + "`" + color.CyanString(` |/ _ \
  ___) | |_| | |_) |__) | |_| | | | (_| |  __/
 |____/ \__,_|_.__/____/ \__,_|_|  \__, |\___|
                                     |___/
`) + fmt.Sprintf("\n  v%s — Passive Subdomain Enumeration Engine\n", version),

	RunE: func(cmd *cobra.Command, args []string) error {
		// Collect domains from all input sources
		domains, err := collectDomains(flagDomain, flagList)
		if err != nil {
			return err
		}
		if len(domains) == 0 {
			return fmt.Errorf("no domains specified — use -d, -l, or pipe domains via stdin")
		}

		// Resolve format
		var fmt_ output.Format
		switch strings.ToLower(flagFormat) {
		case "json":
			fmt_ = output.FormatJSON
		case "silent":
			fmt_ = output.FormatSilent
		default:
			fmt_ = output.FormatPlain
		}

		opts := &runner.Options{
			Domains:      domains,
			Include:      flagSources,
			Exclude:      flagExclude,
			FreeOnly:     flagFreeOnly,
			KeyOnly:      flagKeyOnly,
			NoWildcard:   flagNoWildcard,
			MatchPattern: flagMatchPattern,
			SkipPattern:  flagSkipPattern,
			Format:       fmt_,
			OutputFile:   flagOutput,
			NoColor:      flagNoColor,
			Silent:       flagSilent,
			Verbose:      flagVerbose,
			ConfigPath:   flagConfigPath,
			Timeout:      flagTimeout,
		}

		return runner.Run(opts)
	},
}

// ── sub-commands ──────────────────────────────────────────────────────────────

var listSourcesCmd = &cobra.Command{
	Use:   "sources",
	Short: "List all available sources",
	Run: func(cmd *cobra.Command, args []string) {
		cyan  := color.New(color.FgCyan, color.Bold).SprintFunc()
		green := color.New(color.FgGreen).SprintFunc()
		dim   := color.New(color.FgHiBlack).SprintFunc()
		yellow := color.New(color.FgYellow).SprintFunc()

		all := sources.All()
		fmt.Printf("\n%s  (%d sources)\n\n", cyan("Available Sources"), len(all))
		fmt.Printf("  %-20s  %-8s  %s\n", cyan("Name"), cyan("Key?"), cyan("Description"))
		fmt.Printf("  %s\n", dim(strings.Repeat("─", 60)))

		free := 0
		keyed := 0
		for _, name := range sources.Names() {
			src := all[name]
			keyStr := green("free")
			if src.NeedsKey() {
				keyStr = yellow("key ")
				keyed++
			} else {
				free++
			}
			fmt.Printf("  %-20s  [%s]\n", name, keyStr)
		}
		fmt.Printf("\n  %s free sources, %s require API keys\n\n",
			green(fmt.Sprintf("%d", free)),
			yellow(fmt.Sprintf("%d", keyed)),
		)
	},
}

var initConfigCmd = &cobra.Command{
	Use:   "config",
	Short: "Write a default config file to ~/.config/subsurge/config.yaml",
	RunE: func(cmd *cobra.Command, args []string) error {
		home, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		path := filepath.Join(home, ".config", "subsurge", "config.yaml")
		if err := config.WriteDefault(path); err != nil {
			return err
		}
		fmt.Printf("Config written to: %s\n", path)
		fmt.Println("Edit this file to add your API keys.")
		return nil
	},
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("subsurge v%s\n", version)
	},
}

// ── init ──────────────────────────────────────────────────────────────────────

func init() {
	rootCmd.AddCommand(listSourcesCmd, initConfigCmd, versionCmd)

	f := rootCmd.Flags()

	// Input
	f.StringVarP(&flagDomain, "domain", "d", "", "Target domain (e.g. example.com)")
	f.StringVarP(&flagList, "list", "l", "", "File containing domains (one per line)")

	// Output
	f.StringVarP(&flagOutput, "output", "o", "", "Save results to file")
	f.StringVarP(&flagFormat, "format", "f", "plain", "Output format: plain, json, silent")
	f.BoolVar(&flagSilent, "silent", false, "Only print subdomains (no status messages)")
	f.BoolVar(&flagVerbose, "verbose", false, "Show per-source progress")
	f.BoolVar(&flagNoColor, "no-color", false, "Disable color output")

	// Sources
	f.StringSliceVarP(&flagSources, "sources", "s", nil,
		"Comma-separated list of sources to use (default: all)")
	f.StringSliceVarP(&flagExclude, "exclude-sources", "e", nil,
		"Comma-separated list of sources to skip")
	f.BoolVar(&flagFreeOnly, "free", false, "Only use sources that don't require API keys")
	f.BoolVar(&flagKeyOnly, "key-only", false, "Only use sources that require API keys")

	// Filtering
	f.BoolVar(&flagNoWildcard, "no-wildcard", true,
		"Filter wildcard DNS results (default: true)")
	f.StringVarP(&flagMatchPattern, "match", "m", "",
		"Only include subdomains matching this regex")
	f.StringVar(&flagSkipPattern, "filter", "",
		"Exclude subdomains matching this regex")

	// Misc
	f.IntVar(&flagTimeout, "timeout", 30, "HTTP request timeout in seconds")
	f.StringVar(&flagConfigPath, "config", "", "Path to config file (default: ~/.config/subsurge/config.yaml)")
}

// ── helpers ───────────────────────────────────────────────────────────────────

// collectDomains gathers domains from -d flag, -l file, and stdin pipe.
func collectDomains(domain, listFile string) ([]string, error) {
	seen := make(map[string]struct{})
	var domains []string

	add := func(d string) {
		d = strings.ToLower(strings.TrimSpace(d))
		if d == "" {
			return
		}
		// Strip leading http(s)://
		d = strings.TrimPrefix(d, "https://")
		d = strings.TrimPrefix(d, "http://")
		// Strip trailing slash
		d = strings.TrimSuffix(d, "/")
		if _, ok := seen[d]; !ok {
			seen[d] = struct{}{}
			domains = append(domains, d)
		}
	}

	if domain != "" {
		add(domain)
	}

	if listFile != "" {
		f, err := os.Open(listFile)
		if err != nil {
			return nil, fmt.Errorf("opening domain list %s: %w", listFile, err)
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			add(line)
		}
	}

	// Read from stdin if piped (non-interactive)
	if isStdinPiped() {
		sc := bufio.NewScanner(os.Stdin)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			add(line)
		}
	}

	return domains, nil
}

// isStdinPiped returns true when stdin is not a terminal.
func isStdinPiped() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) == 0
}
