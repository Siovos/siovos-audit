// Package collector defines the transport abstraction for communicating with audit targets.
// Checks use the Collector interface to execute commands and read files,
// without knowing whether the target is reached via SSH, locally, or other means.
package collector

import "context"

// Platform describes the target system.
type Platform struct {
	OS     string
	Arch   string
	Distro string
	Kernel string
}

// Collector is the transport abstraction. All checks interact with the target
// exclusively through this interface, making them transport-agnostic.
type Collector interface {
	// Exec runs a command on the target and returns the combined output.
	Exec(ctx context.Context, cmd string) ([]byte, error)
	// ReadFile reads a file from the target filesystem.
	ReadFile(ctx context.Context, path string) ([]byte, error)
	// Platform returns information about the target system.
	Platform() Platform
	// Target returns a human-readable identifier for the target (e.g. hostname or IP).
	Target() string
	// Close releases any resources held by the collector.
	Close() error
}
