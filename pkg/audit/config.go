package audit

import (
	"os"

	"gopkg.in/yaml.v3"
)

// Config holds user configuration for customizing audit behavior.
type Config struct {
	Profile       string            `yaml:"profile,omitempty"`
	ExpectedPorts []string          `yaml:"expected_ports,omitempty"`
	Suppress      []string          `yaml:"suppress,omitempty"`
	Checks        map[string]CheckConfig `yaml:"checks,omitempty"`
}

// CheckConfig holds per-check overrides.
type CheckConfig struct {
	Enabled   *bool             `yaml:"enabled,omitempty"`
	Options   map[string]string `yaml:"options,omitempty"`
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

// FilterFindings removes suppressed findings and expected port warnings.
func (c *Config) FilterFindings(findings []Finding) []Finding {
	suppressed := make(map[string]bool, len(c.Suppress))
	for _, id := range c.Suppress {
		suppressed[id] = true
	}

	expectedPorts := make(map[string]bool, len(c.ExpectedPorts))
	for _, p := range c.ExpectedPorts {
		expectedPorts[p] = true
	}

	var filtered []Finding
	for _, f := range findings {
		if suppressed[f.ID] {
			continue
		}
		// Skip port warnings for expected ports
		if len(expectedPorts) > 0 {
			for port := range expectedPorts {
				if f.ID == "firewall-open-port-"+port || f.ID == "services-exposed-"+port {
					goto skip
				}
			}
		}
		filtered = append(filtered, f)
		continue
	skip:
	}
	return filtered
}

// IsCheckEnabled returns whether a check should run based on config.
func (c *Config) IsCheckEnabled(checkID string) bool {
	if cc, ok := c.Checks[checkID]; ok && cc.Enabled != nil {
		return *cc.Enabled
	}
	return true
}

// CheckOption returns a per-check option value, or empty string.
func (c *Config) CheckOption(checkID, key string) string {
	if cc, ok := c.Checks[checkID]; ok {
		return cc.Options[key]
	}
	return ""
}
