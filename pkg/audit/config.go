package audit

import (
	"os"

	"gopkg.in/yaml.v3"
)

// Config holds user configuration for suppressing findings and customizing behavior.
type Config struct {
	Suppress []string `yaml:"suppress"` // Finding IDs to suppress (e.g. "firewall-open-port-8080")
}

// LoadConfig reads a config file. Returns an empty config if the file does not exist.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &Config{}, nil
		}
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// FilterFindings removes suppressed findings from the list.
func (c *Config) FilterFindings(findings []Finding) []Finding {
	if len(c.Suppress) == 0 {
		return findings
	}

	suppressed := make(map[string]bool, len(c.Suppress))
	for _, id := range c.Suppress {
		suppressed[id] = true
	}

	var filtered []Finding
	for _, f := range findings {
		if !suppressed[f.ID] {
			filtered = append(filtered, f)
		}
	}
	return filtered
}
