package audit

// Profile is a preset configuration for a common server type.
type Profile struct {
	ID            string
	Name          string
	Description   string
	ExpectedPorts []string
	Checks        []string // Check IDs to enable (empty = all)
}

var Profiles = map[string]Profile{
	"minimal-vps": {
		ID:            "minimal-vps",
		Name:          "Minimal VPS",
		Description:   "Basic VPS with SSH, web server. No Kubernetes or VPN.",
		ExpectedPorts: []string{"22", "80", "443"},
		Checks:        []string{"ssh", "firewall", "tls", "services", "system", "network"},
	},
	"web-server": {
		ID:            "web-server",
		Name:          "Web Server",
		Description:   "Web server with HTTPS. Strict TLS checks.",
		ExpectedPorts: []string{"22", "80", "443"},
		Checks:        []string{"ssh", "firewall", "tls", "services", "system", "network"},
	},
	"kubernetes-node": {
		ID:            "kubernetes-node",
		Name:          "Kubernetes Node",
		Description:   "Server running K8s/K3s with typical control plane ports.",
		ExpectedPorts: []string{"22", "80", "443", "6443", "8443", "10250", "10251", "10252", "53"},
		Checks:        []string{"ssh", "firewall", "tls", "services", "system", "network", "kubernetes"},
	},
	"database-server": {
		ID:            "database-server",
		Name:          "Database Server",
		Description:   "Server hosting databases. No public DB ports expected.",
		ExpectedPorts: []string{"22"},
		Checks:        []string{"ssh", "firewall", "services", "system", "network"},
	},
	"vpn-gateway": {
		ID:            "vpn-gateway",
		Name:          "VPN Gateway",
		Description:   "WireGuard VPN server. VPN checks enabled.",
		ExpectedPorts: []string{"22", "51820"},
		Checks:        []string{"ssh", "firewall", "services", "system", "network", "vpn"},
	},
	"full": {
		ID:            "full",
		Name:          "Full Audit",
		Description:   "Run all checks, no ports pre-expected.",
		ExpectedPorts: []string{},
		Checks:        nil, // nil = all
	},
}

// ProfileList returns all profiles in display order.
func ProfileList() []Profile {
	order := []string{"minimal-vps", "web-server", "kubernetes-node", "database-server", "vpn-gateway", "full"}
	var list []Profile
	for _, id := range order {
		list = append(list, Profiles[id])
	}
	return list
}

// ApplyProfile merges a profile into a config.
// Profile provides the base expected ports, config adds on top.
func (c *Config) ApplyProfile(profileID string) {
	p, ok := Profiles[profileID]
	if !ok {
		return
	}
	// Merge: profile base + user additions (deduplicated)
	seen := make(map[string]bool)
	var merged []string
	for _, port := range p.ExpectedPorts {
		if !seen[port] {
			merged = append(merged, port)
			seen[port] = true
		}
	}
	for _, port := range c.ExpectedPorts {
		if !seen[port] {
			merged = append(merged, port)
			seen[port] = true
		}
	}
	c.ExpectedPorts = merged
}

// DetectProfile guesses the best profile based on what's running.
func DetectProfile(checks map[string]bool) string {
	hasK8s := checks["kubernetes"]
	hasVPN := checks["vpn"]

	if hasK8s && hasVPN {
		return "kubernetes-node"
	}
	if hasK8s {
		return "kubernetes-node"
	}
	if hasVPN {
		return "vpn-gateway"
	}
	return "minimal-vps"
}
