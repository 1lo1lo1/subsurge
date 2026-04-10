# subsurge

**Fast, passive subdomain enumeration engine for bug bounty hunters.**

`subsurge` queries 27 public data sources simultaneously, deduplicates results,
filters wildcards and garbage, and streams output so you can pipe it straight
into your next tool. Written in Go — single binary, no runtime deps.

---

## Features

| Feature | Detail |
|---|---|
| **27 sources** | Free + API-key sources; runs all in parallel |
| **Streaming output** | Results print as they arrive — no waiting |
| **Wildcard detection** | Probes for wildcard DNS and drops false positives |
| **Full pipeline support** | Stdin pipe in, stdout pipe out |
| **Flexible output** | Plain, JSON, silent |
| **Smart filtering** | Regex match/skip, dedup, label validation |
| **API key config** | `~/.config/subsurge/config.yaml` |
| **Source control** | Include or exclude any source by name |
| **Rate limiting** | Per-source throttling in config |
| **Zero cloud** | Runs fully locally; you own your data |

---

## Install

```bash
# From source (requires Go 1.22+)
git clone https://github.com/user/subsurge
cd subsurge
make install       # installs to $(go env GOPATH)/bin

# Or just build a binary
make build         # outputs to ./dist/subsurge

# Cross-compile release binaries for all platforms
make release
```

---

## Quick Start

```bash
# Basic enumeration
subsurge -d example.com

# Save results to file
subsurge -d example.com -o results.txt

# JSON output (for jq / scripts)
subsurge -d example.com -f json -o results.json

# Silent mode — only subdomains, perfect for piping
subsurge -d example.com --silent

# Enumerate multiple domains from a file
subsurge -l domains.txt -o all-results.txt

# Pipe domains in
cat scope.txt | subsurge --silent | httpx -silent | nuclei -t exposures/
```

---

## Pipeline Examples

```bash
# Classic recon pipeline
subsurge -d target.com --silent \
  | dnsx -silent \
  | httpx -silent \
  | nuclei -t cves/

# Feed straight into naabu for port scanning
subsurge -d target.com --silent | naabu -silent

# Combine with subfinder for maximum coverage
{ subfinder -d target.com -silent; subsurge -d target.com --silent; } \
  | sort -u \
  | dnsx -silent

# Filter only staging/dev subdomains
subsurge -d target.com --silent --match "(staging|dev|test|qa)\."

# Multi-domain from scope file, deduplicated
cat bugbounty-scope.txt | subsurge --silent | anew found-subs.txt

# JSON output piped to jq for processing
subsurge -d target.com -f json | jq '.[].domain'
```

---

## All Flags

```
Usage:
  subsurge [flags]
  subsurge [command]

Flags:
  Input:
    -d, --domain string              Target domain (e.g. example.com)
    -l, --list string                File with domains, one per line
                                     (also reads from stdin when piped)

  Output:
    -o, --output string              Save results to file
    -f, --format string              Output format: plain | json | silent (default: plain)
        --silent                     Only print subdomains, no status messages
        --verbose                    Show per-source progress and result counts
        --no-color                   Disable colour output

  Sources:
    -s, --sources strings            Use only these sources (comma-separated)
    -e, --exclude-sources strings    Skip these sources (comma-separated)
        --free                       Only use sources that don't require API keys
        --key-only                   Only use sources that require API keys

  Filtering:
        --no-wildcard                Filter wildcard DNS results (default: true)
    -m, --match string               Only include subdomains matching this regex
        --filter string              Exclude subdomains matching this regex

  Misc:
        --timeout int                HTTP timeout in seconds (default: 30)
        --config string              Config file path (default: ~/.config/subsurge/config.yaml)

Commands:
  sources     List all available data sources
  config      Write default config to ~/.config/subsurge/config.yaml
  version     Print version
```

---

## Sources

Run `subsurge sources` to list all sources. Key sources marked with `[key]`.

| Source | Key? | Notes |
|---|---|---|
| `crtsh` | free | Certificate Transparency, paginated |
| `certspotter` | free | CT logs, paginated |
| `hackertarget` | free | Quick DNS lookup |
| `alienvault` | free | OTX passive DNS |
| `urlscan` | free | Web scan index |
| `threatcrowd` | free | Threat intelligence |
| `threatminer` | free | Threat intelligence |
| `anubis` | free | jonlu.ca subdomain DB |
| `rapiddns` | free | DNS lookup tool |
| `bufferover` | free | FDNS/RDNS dataset |
| `dnsrepo` | free | NOC DNS repo |
| `wayback` | free | Internet Archive CDX |
| `commoncrawl` | free | Web crawl index |
| `dnsdumpster` | free | DNS recon |
| `sublist3r` | free | Sublist3r API |
| `leakix` | free+ | Optional key for more results |
| `virustotal` | **key** | Large VT subdomain DB |
| `securitytrails` | **key** | Excellent historical DNS |
| `shodan` | **key** | Internet scanner |
| `censys` | **key** | TLS cert scan |
| `binaryedge` | **key** | Internet-wide scanner |
| `fullhunt` | **key** | Attack surface mgmt |
| `chaos` | **key** | ProjectDiscovery dataset |
| `netlas` | **key** | Internet scanner |
| `passivetotal` | **key** | RiskIQ passive DNS |
| `hunter` | **key** | Email/domain intel |
| `github` | **key** | Code search dorking |

---

## API Keys Config

```bash
# Write default config
subsurge config

# Edit it
$EDITOR ~/.config/subsurge/config.yaml
```

```yaml
# ~/.config/subsurge/config.yaml
timeout: 30

resolvers:
  - 1.1.1.1
  - 8.8.8.8

rate_limit:
  securitytrails: 2   # 2 req/sec
  shodan: 1

keys:
  virustotal:
    key: "YOUR_VT_KEY"
  securitytrails:
    key: "YOUR_ST_KEY"
  shodan:
    key: "YOUR_SHODAN_KEY"
  censys:
    api_id: "YOUR_CENSYS_ID"
    api_secret: "YOUR_CENSYS_SECRET"
  binaryedge:
    key: "YOUR_BE_KEY"
  fullhunt:
    key: "YOUR_FH_KEY"
  chaos:
    key: "YOUR_CHAOS_KEY"
  github:
    token: "YOUR_GH_TOKEN"   # needs public_repo scope
  passivetotal:
    username: "you@example.com"
    key: "YOUR_PT_KEY"
```

---

## Tips for Bug Bounty

```bash
# Maximum coverage — all sources including keyed ones
subsurge -d target.com --verbose

# Fast recon — free sources only, no API key needed
subsurge -d target.com --free --silent

# Only API sources (after configuring keys) for deeper results
subsurge -d target.com --key-only

# Exclude slow sources for quick pass
subsurge -d target.com -e commoncrawl,wayback,github

# Filter internal/admin panels
subsurge -d target.com --match "(admin|internal|vpn|jenkins|jira)\."

# Continuous monitoring: compare against known list
subsurge -d target.com --silent | anew known-subdomains.txt | notify

# Integrate with amass for DNS brute forcing on top
subsurge -d target.com --silent > passive.txt
amass enum -passive -d target.com >> passive.txt
sort -u passive.txt | dnsx -silent
```

---

## License

MIT
