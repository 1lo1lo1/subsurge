# 🔍 subsurge

Fast, passive subdomain enumeration — **no API keys required**.

subsurge queries **16 free data sources** simultaneously, streams results instantly, and pipes directly into your recon workflow. Written in Go — single binary, no dependencies.

![Go Version](https://img.shields.io/badge/go-%3E%3D1.21-blue)
![License](https://img.shields.io/badge/license-MIT-green)

## ⚡ Features

- **16 Free Sources** — No registration, no API keys
- **Streaming Output** — Results print as they arrive
- **Wildcard Detection** — Auto-drops false positives
- **Pipeline Ready** — `stdin` in, `stdout` out
- **Multiple Formats** — Plain, JSON, silent
- **Smart Filtering** — Regex match/skip, deduplication

## 📦 Installation

### From Source (Go 1.21+)
```bash
git clone https://github.com/1lo1lo1/subsurge.git
cd subsurge
go build -o subsurge cmd/subsurge/main.go
sudo mv subsurge /usr/local/bin/

🚀 Quick Start
# Basic scan — no setup needed!
subsurge -d example.com --free

# Silent mode for piping
subsurge -d example.com --free --silent | httpx -silent

# Multiple domains
cat domains.txt | subsurge --free --silent | anew found.txt

# JSON output
subsurge -d example.com --free -f json -o results.json

🔧 Pipeline Examples
# Classic recon
subsurge -d target.com --free --silent | dnsx -silent | httpx -silent | nuclei -t cves/

# Port scanning
subsurge -d target.com --free --silent | naabu -silent

# Filter staging/dev environments
subsurge -d target.com --free --silent --match "(staging|dev|test|qa)\."

# Combine with subfinder
{ subfinder -d target.com -silent; subsurge -d target.com --free --silent; } | sort -u | dnsx -silent

📋 All Flags
| Flag                    | Description                         |
| ----------------------- | ----------------------------------- |
| `-d, --domain`          | Target domain                       |
| `-l, --list`            | File with domains                   |
| `-o, --output`          | Save to file                        |
| `-f, --format`          | Output: `plain`, `json`, `silent`   |
| `--free`                | **Only free sources (no API keys)** |
| `--silent`              | Domains only, no banners            |
| `--verbose`             | Show source progress                |
| `-m, --match`           | Regex to include                    |
| `--filter`              | Regex to exclude                    |
| `-e, --exclude-sources` | Skip specific sources               |
| `--timeout`             | HTTP timeout (default: 30s)         |

🌐 Free Sources (No API Key)
| Source       | Type                     |
| ------------ | ------------------------ |
| crt.sh       | Certificate Transparency |
| certspotter  | CT logs                  |
| hackertarget | DNS lookup               |
| alienvault   | OTX passive DNS          |
| urlscan      | Web scan index           |
| threatcrowd  | Threat intel             |
| threatminer  | Threat intel             |
| anubis       | Subdomain DB             |
| rapiddns     | DNS lookup               |
| bufferover   | FDNS dataset             |
| dnsrepo      | DNS repository           |
| wayback      | Internet Archive         |
| commoncrawl  | Web crawl index          |
| dnsdumpster  | DNS recon                |
| sublist3r    | Sublist3r API            |
| leakix       | Leaks DB (limited)       |

🔑 Optional: API Keys (More Sources)
Want 27 total sources? Add API keys for deeper results:
# Generate config template
subsurge config
# Edit: ~/.config/subsurge/config.yaml

🏗️ Architecture
cmd/          → CLI entrypoint
internal/     → Core logic
├── filter/   → Deduplication, wildcards
├── output/   → Formatters
├── ratelimit/→ Token bucket
├── runner/   → Parallel orchestration
└── sources/  → 16 free + 11 keyed implementations
pkg/models/   → Shared types

## 🤝 Contributing

PRs welcome! Run `go fmt ./...` before submitting.

## 📜 License

MIT
