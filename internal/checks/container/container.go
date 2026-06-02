package container

import (
	"context"
	"fmt"
	"strings"

	"github.com/Siovos/siovos-audit/pkg/audit"
	"github.com/Siovos/siovos-audit/pkg/collector"
)

type Check struct{}

func New() *Check { return &Check{} }

func (c *Check) ID() string       { return "container" }
func (c *Check) Name() string     { return "Container Runtime" }
func (c *Check) Category() string { return "container" }

func (c *Check) Run(ctx context.Context, col collector.Collector) ([]audit.Finding, error) {
	out, err := col.Exec(ctx, "docker info 2>/dev/null")
	if err != nil || strings.TrimSpace(string(out)) == "" {
		return []audit.Finding{{
			ID: "container-none", CheckID: "container",
			Severity: audit.SeverityInfo,
			Title:    "Docker not detected",
		}}, nil
	}

	var findings []audit.Finding
	findings = append(findings, audit.Finding{
		ID: "container-docker", CheckID: "container",
		Severity: audit.SeverityInfo,
		Title:    "Docker is running",
	})

	findings = append(findings, checkDockerSocket(ctx, col)...)
	findings = append(findings, checkPrivilegedContainers(ctx, col)...)
	findings = append(findings, checkDangerousVolumes(ctx, col)...)

	return findings, nil
}

func checkDockerSocket(ctx context.Context, col collector.Collector) []audit.Finding {
	out, err := col.Exec(ctx, "stat -c '%a %G' /var/run/docker.sock 2>/dev/null")
	if err != nil {
		return nil
	}
	fields := strings.Fields(strings.TrimSpace(string(out)))
	if len(fields) < 2 {
		return nil
	}
	perms := fields[0]
	group := fields[1]

	if perms == "660" && group == "docker" {
		return []audit.Finding{{
			ID: "container-socket-perms", CheckID: "container",
			Severity: audit.SeverityPass,
			Title:    "Docker socket permissions OK (660, group docker)",
		}}
	}
	if perms == "666" {
		return []audit.Finding{{
			ID: "container-socket-perms", CheckID: "container",
			Severity:    audit.SeverityCritical,
			Title:       "Docker socket world-accessible (666)",
			Remediation: "chmod 660 /var/run/docker.sock",
		}}
	}
	return []audit.Finding{{
		ID: "container-socket-perms", CheckID: "container",
		Severity: audit.SeverityInfo,
		Title:    fmt.Sprintf("Docker socket: %s (group: %s)", perms, group),
	}}
}

func checkPrivilegedContainers(ctx context.Context, col collector.Collector) []audit.Finding {
	out, err := col.Exec(ctx, `docker ps --format '{{.Names}}' -q 2>/dev/null | xargs -I{} docker inspect --format '{{.Name}} {{.HostConfig.Privileged}}' {} 2>/dev/null | grep true`)
	if err != nil || strings.TrimSpace(string(out)) == "" {
		return []audit.Finding{{
			ID: "container-privileged", CheckID: "container",
			Severity: audit.SeverityPass,
			Title:    "No privileged containers running",
		}}
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	return []audit.Finding{{
		ID:          "container-privileged",
		CheckID:     "container",
		Severity:    audit.SeverityFail,
		Title:       fmt.Sprintf("Privileged containers: %d", len(lines)),
		Evidence:    strings.TrimSpace(string(out)),
		Remediation: "Remove --privileged flag. Use specific capabilities instead.",
	}}
}

func checkDangerousVolumes(ctx context.Context, col collector.Collector) []audit.Finding {
	dangerous := []string{"/:/", "docker.sock", "/etc:/"}
	out, err := col.Exec(ctx, `docker ps -q 2>/dev/null | xargs -I{} docker inspect --format '{{.Name}} {{range .Mounts}}{{.Source}}:{{.Destination}} {{end}}' {} 2>/dev/null`)
	if err != nil {
		return nil
	}

	var findings []audit.Finding
	for _, line := range strings.Split(string(out), "\n") {
		for _, d := range dangerous {
			if strings.Contains(line, d) {
				name := strings.Fields(line)
				cname := "unknown"
				if len(name) > 0 {
					cname = name[0]
				}
				findings = append(findings, audit.Finding{
					ID:          "container-dangerous-volume-" + sanitize(cname),
					CheckID:     "container",
					Severity:    audit.SeverityFail,
					Title:       fmt.Sprintf("Dangerous volume mount in %s: %s", cname, d),
					Remediation: "Avoid mounting /, /etc, or docker.sock into containers",
				})
			}
		}
	}
	return findings
}

func sanitize(s string) string {
	r := strings.NewReplacer("/", "", " ", "-")
	s = r.Replace(strings.ToLower(s))
	if len(s) > 30 {
		s = s[:30]
	}
	return s
}
