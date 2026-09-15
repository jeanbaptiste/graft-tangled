// Package config loads the bridge's JSON configuration file.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// Duration wraps time.Duration for JSON strings like "30s".
type Duration struct{ time.Duration }

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	d.Duration = v
	return nil
}

func (d Duration) D() time.Duration {
	if d.Duration == 0 {
		return 30 * time.Second
	}
	return d.Duration
}

// SeriesTarget is one Graft series to mirror to Tangled.
type SeriesTarget struct {
	Series      string `json:"series"`
	Knot        string `json:"knot"`
	Source      string `json:"source"` // git clone URL the knot imports from
	Description string `json:"description"`
}

// Config is the bridge's full configuration.
type Config struct {
	Listen               string   `json:"listen"`
	PublicBaseURL        string   `json:"public_base_url"`
	ActorName            string   `json:"actor_name"`
	StateFile            string   `json:"state_file"`
	RepoURL              string   `json:"repo_url"`
	PollInterval         Duration `json:"poll_interval"`
	PassTimeout          Duration `json:"pass_timeout"`
	AdminToken           string   `json:"admin_token"`
	MaxContentRunes      int      `json:"max_content_runes"`
	MaxDeliveriesPerPass int      `json:"max_deliveries_per_pass"`

	Graft struct {
		BaseURL string         `json:"base_url"`
		Series  []SeriesTarget `json:"series"`
	} `json:"graft"`

	Tangled struct {
		PDSBaseURL      string `json:"pds_base_url"`
		Handle          string `json:"handle"`
		AppPasswordFile string `json:"app_password_file"`
		AppviewDBPath   string `json:"appview_db_path"`
		// WebBaseURL is the Tangled web UI (the appview) that trackback
		// links point at, e.g. https://tangled.example.org. Optional:
		// without it no trackback is sent.
		WebBaseURL string `json:"web_base_url"`
	} `json:"tangled"`
}

// Load reads and lightly validates the config file at path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if cfg.Graft.BaseURL == "" {
		return nil, fmt.Errorf("graft.base_url is required")
	}
	if cfg.Tangled.PDSBaseURL == "" || cfg.Tangled.Handle == "" || cfg.Tangled.AppPasswordFile == "" {
		return nil, fmt.Errorf("tangled.pds_base_url, handle and app_password_file are required")
	}
	if cfg.Tangled.AppviewDBPath == "" {
		return nil, fmt.Errorf("tangled.appview_db_path is required")
	}
	if cfg.PublicBaseURL == "" {
		return nil, fmt.Errorf("public_base_url is required — Graft must be able to fetch this bridge's actor over HTTPS to verify deliveries")
	}
	if cfg.StateFile == "" {
		return nil, fmt.Errorf("state_file is required")
	}
	for i, s := range cfg.Graft.Series {
		if s.Series == "" || s.Knot == "" || s.Source == "" {
			return nil, fmt.Errorf("graft.series[%d]: series, knot and source are required", i)
		}
	}
	return &cfg, nil
}

// ReadToken reads a secret from a file, trimming surrounding whitespace —
// same convention as Graft's own config.ReadToken.
func ReadToken(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read token file %s: %w", path, err)
	}
	token := string(data)
	for len(token) > 0 && (token[len(token)-1] == '\n' || token[len(token)-1] == '\r' || token[len(token)-1] == ' ') {
		token = token[:len(token)-1]
	}
	if token == "" {
		return "", fmt.Errorf("token file %s is empty", path)
	}
	return token, nil
}
