package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server  ServerConfig        `yaml:"server"`
	Storage StorageConfig       `yaml:"storage"`
	Keys    map[string]KeyConfig `yaml:"keys"`
}

type ServerConfig struct {
	Listen           string    `yaml:"listen"`
	TLS              TLSConfig `yaml:"tls"`
	ClockSkewSeconds int       `yaml:"clock_skew_seconds"`
	// Format restricts the entire server to one upload format: "yaml" or "raw".
	// When set, the opposing family of endpoints (/zones/{zone} for "raw",
	// /data for "yaml") returns 403 for all clients, regardless of per-key
	// format settings.  Leave empty for no server-wide restriction (default).
	Format string `yaml:"format"`
}

type TLSConfig struct {
	Cert string `yaml:"cert"`
	Key  string `yaml:"key"`
}

type StorageConfig struct {
	ZonesDir       string `yaml:"zones_dir"`
	RebuildCommand string `yaml:"rebuild_command"`
}

type KeyConfig struct {
	PublicKey      string   `yaml:"public_key"`
	AllowedZones   []string `yaml:"allowed_zones"`
	AllowMerge     bool     `yaml:"allow_merge"`
	AllowReplace   bool     `yaml:"allow_replace"`
	AllowRawUpload bool     `yaml:"allow_raw_upload"`
	// Format restricts a key to one storage format: "yaml" or "raw".
	// When set, the server rejects uploads in the other format and removes
	// any previously stored files in the other format on each successful write.
	// Leave empty for no restriction (backwards-compatible default).
	Format string `yaml:"format"`
}

func Load(path string) (*Config, error) {
	if path == "" {
		path = os.Getenv("TINYDNS_CONFIG")
	}
	if path == "" {
		path = "/etc/tinydns-sidecar/config.yml"
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening config %s: %w", path, err)
	}
	defer f.Close()

	cfg := &Config{}
	dec := yaml.NewDecoder(f)
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil {
		return nil, fmt.Errorf("parsing config %s: %w", path, err)
	}

	// Apply defaults
	if cfg.Server.Listen == "" {
		cfg.Server.Listen = ":8080"
	}
	if cfg.Server.ClockSkewSeconds == 0 {
		cfg.Server.ClockSkewSeconds = 300
	}

	// Validate format fields.
	validFormats := map[string]bool{"": true, "yaml": true, "raw": true}
	if !validFormats[cfg.Server.Format] {
		return nil, fmt.Errorf("server.format must be \"yaml\", \"raw\", or empty; got %q", cfg.Server.Format)
	}
	for id, kc := range cfg.Keys {
		if !validFormats[kc.Format] {
			return nil, fmt.Errorf("keys[%s].format must be \"yaml\", \"raw\", or empty; got %q", id, kc.Format)
		}
	}

	return cfg, nil
}
