package audit

import (
	"context"
	"strings"

	"github.com/Siovos/siovos-audit/pkg/collector"
)

// Facts holds pre-gathered server state shared across all checks.
// Populated once during the gather phase, then read by checks for cross-referencing.
type Facts struct {
	// Firewall
	UFWActive      bool
	UFWDefaultDeny bool
	PublicPorts    map[string]bool // Ports allowed from Anywhere through UFW

	// Network
	ListeningPorts []PortFact

	// System
	InstalledPackages map[string]bool
	SystemdServices   []ServiceFact
	Users             []UserFact

	// Runtime
	Processes []ProcessFact
}

// PortFact describes a listening port.
type PortFact struct {
	Port    string
	Address string
	Process string
}

// ServiceFact describes a systemd service.
type ServiceFact struct {
	Name    string
	Active  bool
	Enabled bool
}

// UserFact describes a system user.
type UserFact struct {
	Name  string
	UID   string
	Shell string
	Home  string
}

// ProcessFact describes a running process.
type ProcessFact struct {
	PID  string
	User string
	Cmd  string
}

// GatherFacts collects server state that multiple checks will need.
// This runs once before checks execute, avoiding duplicate commands.
func GatherFacts(ctx context.Context, col collector.Collector) *Facts {
	f := &Facts{
		PublicPorts:       make(map[string]bool),
		InstalledPackages: make(map[string]bool),
	}

	f.gatherUFW(ctx, col)
	f.gatherListeningPorts(ctx, col)
	f.gatherUsers(ctx, col)
	f.gatherServices(ctx, col)

	return f
}

func (f *Facts) gatherUFW(ctx context.Context, col collector.Collector) {
	out, err := col.Exec(ctx, "ufw status 2>/dev/null")
	if err != nil {
		return
	}

	output := string(out)
	f.UFWActive = strings.Contains(output, "Status: active")
	if !f.UFWActive {
		return
	}

	// Check default deny
	verbose, err := col.Exec(ctx, "ufw status verbose 2>/dev/null")
	if err == nil {
		f.UFWDefaultDeny = strings.Contains(string(verbose), "Default: deny (incoming)")
	}

	// Parse publicly allowed ports
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if !strings.Contains(line, "ALLOW") || strings.Contains(line, "ALLOW OUT") {
			continue
		}
		// Only "Anywhere" source = public (not specific subnets, not v6 duplicates)
		if !strings.Contains(line, "Anywhere") || strings.Contains(line, "(v6)") || strings.Contains(line, "on ") {
			continue
		}
		// Check it's not from a specific subnet (would have / in the from field)
		parts := strings.Fields(line)
		if len(parts) >= 4 {
			from := parts[len(parts)-1]
			if strings.Contains(from, "/") && from != "Anywhere" {
				continue
			}
		}

		if len(parts) > 0 {
			port := extractPort(parts[0])
			if port != "" {
				f.PublicPorts[port] = true
			}
		}
	}
}

func (f *Facts) gatherListeningPorts(ctx context.Context, col collector.Collector) {
	out, err := col.Exec(ctx, "ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null")
	if err != nil {
		return
	}

	for _, line := range strings.Split(string(out), "\n")[1:] {
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		addr := fields[3]
		port := extractPort(addr)
		process := ""
		if len(fields) >= 6 {
			process = fields[len(fields)-1]
		}
		f.ListeningPorts = append(f.ListeningPorts, PortFact{
			Port:    port,
			Address: addr,
			Process: process,
		})
	}
}

func (f *Facts) gatherUsers(ctx context.Context, col collector.Collector) {
	out, err := col.Exec(ctx, "cat /etc/passwd 2>/dev/null")
	if err != nil {
		return
	}

	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		parts := strings.Split(line, ":")
		if len(parts) < 7 {
			continue
		}
		f.Users = append(f.Users, UserFact{
			Name:  parts[0],
			UID:   parts[2],
			Shell: parts[6],
			Home:  parts[5],
		})
	}
}

func (f *Facts) gatherServices(ctx context.Context, col collector.Collector) {
	out, err := col.Exec(ctx, "systemctl list-units --type=service --all --no-legend --no-pager 2>/dev/null")
	if err != nil {
		return
	}

	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		name := strings.TrimSuffix(fields[0], ".service")
		f.SystemdServices = append(f.SystemdServices, ServiceFact{
			Name:   name,
			Active: fields[2] == "active",
		})
	}
}

// IsPortPublic returns true if a port is both listening and allowed through the firewall.
func (f *Facts) IsPortPublic(port string) bool {
	if !f.UFWActive {
		// No UFW = can't determine, assume listening = exposed
		return true
	}
	if !f.UFWDefaultDeny {
		// No default deny = everything is open
		return true
	}
	return f.PublicPorts[port]
}

// IsPortListening returns true if a port is listening on any interface.
func (f *Facts) IsPortListening(port string) bool {
	for _, p := range f.ListeningPorts {
		if p.Port == port {
			return true
		}
	}
	return false
}

// HasUser returns true if a user exists on the system.
func (f *Facts) HasUser(name string) bool {
	for _, u := range f.Users {
		if u.Name == name {
			return true
		}
	}
	return false
}

// IsServiceActive returns true if a systemd service is active.
func (f *Facts) IsServiceActive(name string) bool {
	for _, s := range f.SystemdServices {
		if s.Name == name && s.Active {
			return true
		}
	}
	return false
}

func extractPort(addr string) string {
	if idx := strings.Index(addr, "/"); idx > 0 {
		return addr[:idx]
	}
	parts := strings.Split(addr, ":")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return ""
}
