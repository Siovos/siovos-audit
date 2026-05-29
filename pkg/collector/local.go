package collector

import (
	"context"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

type LocalCollector struct {
	platform Platform
}

func NewLocalCollector() (*LocalCollector, error) {
	c := &LocalCollector{}
	if err := c.detectPlatform(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *LocalCollector) Exec(ctx context.Context, cmd string) ([]byte, error) {
	return exec.CommandContext(ctx, "sh", "-c", cmd).CombinedOutput()
}

func (c *LocalCollector) ReadFile(_ context.Context, path string) ([]byte, error) {
	return os.ReadFile(path)
}

func (c *LocalCollector) Platform() Platform {
	return c.platform
}

func (c *LocalCollector) Target() string {
	hostname, _ := os.Hostname()
	return hostname + " (local)"
}

func (c *LocalCollector) Close() error {
	return nil
}

func (c *LocalCollector) detectPlatform() error {
	c.platform = Platform{
		OS:   runtime.GOOS,
		Arch: runtime.GOARCH,
	}

	if runtime.GOOS == "linux" {
		if out, err := exec.Command("uname", "-r").Output(); err == nil {
			c.platform.Kernel = strings.TrimSpace(string(out))
		}
		if data, err := os.ReadFile("/etc/os-release"); err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				if strings.HasPrefix(line, "PRETTY_NAME=") {
					c.platform.Distro = strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), "\"")
					break
				}
			}
		}
	}

	return nil
}
