package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Config is the top-level config structure loaded from ~/.config/subsurge/config.yaml
type Config struct {
	// API keys for sources that require authentication
	Keys map[string]map[string]string `yaml:"keys"`

	// RateLimit controls per-source request throttling (req/sec)
	RateLimit map[string]float64 `yaml:"rate_limit"`

	// Timeout is the default HTTP timeout in seconds
	Timeout int `yaml:"timeout"`

	// ResolverList is a custom list of DNS resolvers (empty = system default)
	Resolvers []string `yaml:"resolvers"`
}

var DefaultConfig = Config{
	Keys:      make(map[string]map[string]string),
	RateLimit: map[string]float64{},
	Timeout:   30,
}

// Load reads config from the default location or the given path.
// If the file doesn't exist it silently returns defaults.
func Load(path string) (*Config, error) {
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return &DefaultConfig, nil
		}
		path = filepath.Join(home, ".config", "subsurge", "config.yaml")
	}

	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return &DefaultConfig, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading config %s: %w", path, err)
	}

	cfg := DefaultConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config %s: %w", path, err)
	}
	if cfg.Keys == nil {
		cfg.Keys = make(map[string]map[string]string)
	}
	if cfg.RateLimit == nil {
		cfg.RateLimit = make(map[string]float64)
	}
	return &cfg, nil
}

// WriteDefault writes a commented example config to the given path.
func WriteDefault(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(exampleConfig), 0640)
}

const exampleConfig = `# subsurge configuration
# Place this file at ~/.config/subsurge/config.yaml

# HTTP timeout in seconds (default 30)
timeout: 30

# Custom DNS resolvers (leave empty to use system defaults)
resolvers:
  - 1.1.1.1
  - 8.8.8.8

# Per-source rate limits (requests per second)
# rate_limit:
#   securitytrails: 2
#   shodan: 1

# API keys for sources that require authentication
keys:
  virustotal:
    key: ""            # https://www.virustotal.com/gui/my-apikey
  securitytrails:
    key: ""            # https://securitytrails.com/app/account/credentials
  shodan:
    key: ""            # https://account.shodan.io
  censys:
    api_id: ""         # https://search.censys.io/account/api
    api_secret: ""
  binaryedge:
    key: ""            # https://app.binaryedge.io/account/api
  fullhunt:
    key: ""            # https://fullhunt.io/user/api
  chaos:
    key: ""            # https://chaos.projectdiscovery.io
  github:
    token: ""          # https://github.com/settings/tokens  (public_repo scope)
  passivetotal:
    username: ""       # https://community.riskiq.com/registration
    key: ""
  hunter:
    key: ""            # https://hunter.io/api-keys
  netlas:
    key: ""            # https://app.netlas.io/profile/
  leakix:
    key: ""            # https://leakix.net/settings/api
`
