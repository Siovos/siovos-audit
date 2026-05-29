// Package plugin provides a system for loading external checks as plugins.
// A plugin is an executable that receives a JSON request on stdin and writes
// JSON findings to stdout.
package plugin

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"

	"github.com/Siovos/siovos-audit/pkg/audit"
	"github.com/Siovos/siovos-audit/pkg/collector"
)

// ExternalCheck wraps an external plugin binary as a Check.
type ExternalCheck struct {
	id       string
	name     string
	category string
	path     string
}

// NewExternalCheck creates a check backed by an external binary.
func NewExternalCheck(id, name, category, path string) *ExternalCheck {
	return &ExternalCheck{id: id, name: name, category: category, path: path}
}

func (c *ExternalCheck) ID() string       { return c.id }
func (c *ExternalCheck) Name() string     { return c.name }
func (c *ExternalCheck) Category() string { return c.category }

// PluginRequest is sent to the plugin via stdin.
type PluginRequest struct {
	Target   string             `json:"target"`
	Platform collector.Platform `json:"platform"`
}

// PluginResponse is received from the plugin via stdout.
type PluginResponse struct {
	Findings []audit.Finding `json:"findings"`
	Error    string          `json:"error,omitempty"`
}

func (c *ExternalCheck) Run(ctx context.Context, col collector.Collector) ([]audit.Finding, error) {
	input, err := json.Marshal(PluginRequest{
		Target:   col.Target(),
		Platform: col.Platform(),
	})
	if err != nil {
		return nil, err
	}

	cmd := exec.CommandContext(ctx, c.path)
	cmd.Stdin = bytes.NewReader(input)

	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("plugin %s: %w", c.path, err)
	}

	var resp PluginResponse
	if err := json.Unmarshal(output, &resp); err != nil {
		return nil, fmt.Errorf("plugin %s: invalid output: %w", c.path, err)
	}

	if resp.Error != "" {
		return nil, fmt.Errorf("plugin %s: %s", c.path, resp.Error)
	}

	return resp.Findings, nil
}
