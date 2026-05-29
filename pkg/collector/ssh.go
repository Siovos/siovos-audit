package collector

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"
)

type SSHCollector struct {
	client   *ssh.Client
	host     string
	platform Platform
}

type SSHOptions struct {
	Host       string
	Port       int
	User       string
	KeyPath    string
	Password   string
}

func NewSSHCollector(opts SSHOptions) (*SSHCollector, error) {
	if opts.Port == 0 {
		opts.Port = 22
	}

	config := &ssh.ClientConfig{
		User:            opts.User,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	if opts.KeyPath != "" {
		key, err := os.ReadFile(opts.KeyPath)
		if err != nil {
			return nil, fmt.Errorf("reading SSH key: %w", err)
		}
		signer, err := ssh.ParsePrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("parsing SSH key: %w", err)
		}
		config.Auth = []ssh.AuthMethod{ssh.PublicKeys(signer)}
	} else if opts.Password != "" {
		config.Auth = []ssh.AuthMethod{ssh.Password(opts.Password)}
	} else {
		// Try default key paths
		for _, path := range defaultKeyPaths() {
			key, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			signer, err := ssh.ParsePrivateKey(key)
			if err != nil {
				continue
			}
			config.Auth = append(config.Auth, ssh.PublicKeys(signer))
		}
		if len(config.Auth) == 0 {
			return nil, fmt.Errorf("no SSH authentication method available")
		}
	}

	addr := net.JoinHostPort(opts.Host, fmt.Sprintf("%d", opts.Port))
	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return nil, fmt.Errorf("connecting to %s: %w", addr, err)
	}

	c := &SSHCollector{
		client: client,
		host:   opts.Host,
	}

	if err := c.detectPlatform(); err != nil {
		client.Close()
		return nil, err
	}

	return c, nil
}

func (c *SSHCollector) Exec(ctx context.Context, cmd string) ([]byte, error) {
	session, err := c.client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("creating SSH session: %w", err)
	}
	defer session.Close()

	return session.CombinedOutput(cmd)
}

func (c *SSHCollector) ReadFile(ctx context.Context, path string) ([]byte, error) {
	return c.Exec(ctx, fmt.Sprintf("cat %q", path))
}

func (c *SSHCollector) Platform() Platform {
	return c.platform
}

func (c *SSHCollector) Target() string {
	return c.host
}

func (c *SSHCollector) Close() error {
	return c.client.Close()
}

func (c *SSHCollector) detectPlatform() error {
	ctx := context.Background()

	if out, err := c.Exec(ctx, "uname -s"); err == nil {
		c.platform.OS = strings.TrimSpace(strings.ToLower(string(out)))
	}
	if out, err := c.Exec(ctx, "uname -m"); err == nil {
		c.platform.Arch = strings.TrimSpace(string(out))
	}
	if out, err := c.Exec(ctx, "uname -r"); err == nil {
		c.platform.Kernel = strings.TrimSpace(string(out))
	}
	if out, err := c.Exec(ctx, "cat /etc/os-release"); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			if strings.HasPrefix(line, "PRETTY_NAME=") {
				c.platform.Distro = strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), "\"")
				break
			}
		}
	}

	return nil
}

func defaultKeyPaths() []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	return []string{
		home + "/.ssh/id_ed25519",
		home + "/.ssh/id_rsa",
		home + "/.ssh/id_ecdsa",
	}
}
