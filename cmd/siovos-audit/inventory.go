package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/Siovos/siovos-audit/pkg/collector"
)

type inventoryFlags struct {
	host    string
	user    string
	port    int
	keyPath string
	local   bool
	format  string
}

func newInventoryCmd() *cobra.Command {
	f := &inventoryFlags{}

	cmd := &cobra.Command{
		Use:   "inventory",
		Short: "List everything running on a server",
		Long:  "Inventory shows packages, processes, users, cron jobs, services, and recent file changes. No scoring — just transparency.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runInventory(cmd.Context(), f)
		},
	}

	cmd.Flags().StringVar(&f.host, "host", "", "Target host")
	cmd.Flags().StringVar(&f.user, "user", "", "SSH user")
	cmd.Flags().IntVar(&f.port, "port", 22, "SSH port")
	cmd.Flags().StringVar(&f.keyPath, "key", "", "SSH private key path")
	cmd.Flags().BoolVar(&f.local, "local", false, "Inventory local machine")
	cmd.Flags().StringVar(&f.format, "format", "terminal", "Output: terminal, json")

	return cmd
}

type InventoryResult struct {
	Target   string            `json:"target"`
	Platform string            `json:"platform"`
	Packages PackageInventory  `json:"packages"`
	Users    []UserEntry       `json:"users"`
	Services []ServiceEntry    `json:"services"`
	Cron     []CronEntry       `json:"cron"`
	Procs    []ProcessEntry    `json:"processes"`
	Recent   []RecentFileEntry `json:"recent_files"`
}

type PackageInventory struct {
	Total       int      `json:"total"`
	ManuallySet []string `json:"manually_installed,omitempty"`
}

type UserEntry struct {
	Name  string `json:"name"`
	UID   string `json:"uid"`
	Shell string `json:"shell"`
	Home  string `json:"home"`
}

type ServiceEntry struct {
	Name   string `json:"name"`
	Active bool   `json:"active"`
}

type CronEntry struct {
	User    string `json:"user"`
	Schedule string `json:"schedule"`
	Command string `json:"command"`
}

type ProcessEntry struct {
	PID  string `json:"pid"`
	User string `json:"user"`
	CPU  string `json:"cpu"`
	Mem  string `json:"mem"`
	Cmd  string `json:"cmd"`
}

type RecentFileEntry struct {
	Path    string `json:"path"`
	ModTime string `json:"mod_time"`
}

func runInventory(ctx context.Context, f *inventoryFlags) error {
	var col collector.Collector
	var err error

	if f.local {
		col, err = collector.NewLocalCollector()
	} else if f.host != "" {
		col, err = collector.NewSSHCollector(collector.SSHOptions{
			Host: f.host, Port: f.port, User: f.user, KeyPath: f.keyPath,
		})
	} else {
		return fmt.Errorf("either --host or --local is required")
	}
	if err != nil {
		return err
	}
	defer col.Close()

	cached := collector.NewCachedCollector(col)
	result := gatherInventory(ctx, cached)

	if f.format == "json" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(result)
	}

	printInventory(result)
	return nil
}

func gatherInventory(ctx context.Context, col collector.Collector) *InventoryResult {
	r := &InventoryResult{
		Target:   col.Target(),
		Platform: col.Platform().Distro,
	}

	// Packages
	out, err := col.Exec(ctx, "dpkg -l 2>/dev/null | grep '^ii' | wc -l")
	if err == nil {
		_, _ = fmt.Sscanf(strings.TrimSpace(string(out)), "%d", &r.Packages.Total)
	}
	out, err = col.Exec(ctx, "apt-mark showmanual 2>/dev/null | head -50")
	if err == nil && strings.TrimSpace(string(out)) != "" {
		for _, pkg := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			if pkg != "" {
				r.Packages.ManuallySet = append(r.Packages.ManuallySet, pkg)
			}
		}
	}

	// Users (UID >= 1000 + root)
	out, err = col.Exec(ctx, "awk -F: '$3 >= 1000 || $3 == 0 {print $1\"|\"$3\"|\"$6\"|\"$7}' /etc/passwd 2>/dev/null")
	if err == nil {
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			parts := strings.Split(line, "|")
			if len(parts) >= 4 {
				r.Users = append(r.Users, UserEntry{
					Name: parts[0], UID: parts[1], Home: parts[2], Shell: parts[3],
				})
			}
		}
	}

	// Services
	out, err = col.Exec(ctx, "systemctl list-units --type=service --state=active --no-pager --no-legend 2>/dev/null")
	if err == nil {
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 1 {
				name := strings.TrimSuffix(fields[0], ".service")
				r.Services = append(r.Services, ServiceEntry{Name: name, Active: true})
			}
		}
	}

	// Cron
	out, err = col.Exec(ctx, "for user in $(cut -f1 -d: /etc/passwd); do crontab -l -u $user 2>/dev/null | grep -v '^#' | grep -v '^$' | while read line; do echo \"$user|$line\"; done; done")
	if err == nil {
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			if line == "" {
				continue
			}
			parts := strings.SplitN(line, "|", 2)
			if len(parts) == 2 {
				fields := strings.Fields(parts[1])
				schedule := ""
				command := parts[1]
				if len(fields) >= 6 {
					schedule = strings.Join(fields[:5], " ")
					command = strings.Join(fields[5:], " ")
				}
				r.Cron = append(r.Cron, CronEntry{
					User: parts[0], Schedule: schedule, Command: command,
				})
			}
		}
	}

	// Processes (top by CPU)
	out, err = col.Exec(ctx, "ps aux --sort=-%cpu 2>/dev/null | head -21")
	if err == nil {
		for _, line := range strings.Split(string(out), "\n")[1:] {
			fields := strings.Fields(line)
			if len(fields) >= 11 {
				r.Procs = append(r.Procs, ProcessEntry{
					User: fields[0],
					PID:  fields[1],
					CPU:  fields[2],
					Mem:  fields[3],
					Cmd:  strings.Join(fields[10:], " "),
				})
			}
		}
	}

	// Recently modified files in sensitive directories
	out, err = col.Exec(ctx, "find /etc /usr/bin /usr/sbin -maxdepth 2 -mtime -7 -type f 2>/dev/null | head -30")
	if err == nil {
		for _, path := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			if path == "" {
				continue
			}
			modOut, modErr := col.Exec(ctx, fmt.Sprintf("stat -c '%%y' %q 2>/dev/null", path))
			modTime := ""
			if modErr == nil {
				modTime = strings.TrimSpace(string(modOut))
				if idx := strings.Index(modTime, "."); idx > 0 {
					modTime = modTime[:idx]
				}
			}
			r.Recent = append(r.Recent, RecentFileEntry{Path: path, ModTime: modTime})
		}
	}

	return r
}

func printInventory(r *InventoryResult) {
	w := os.Stdout
	fmt.Fprintf(w, "\n  \033[1mServer Inventory\033[0m\n")
	fmt.Fprintf(w, "  \033[2mTarget: %s (%s)\033[0m\n\n", r.Target, r.Platform)

	// Users
	fmt.Fprintf(w, "  \033[1mUsers\033[0m (%d)\n", len(r.Users))
	for _, u := range r.Users {
		fmt.Fprintf(w, "    %-15s uid=%-5s %s  %s\n", u.Name, u.UID, u.Home, u.Shell)
	}
	fmt.Fprintln(w)

	// Services
	fmt.Fprintf(w, "  \033[1mActive Services\033[0m (%d)\n", len(r.Services))
	for _, s := range r.Services {
		fmt.Fprintf(w, "    %s\n", s.Name)
	}
	fmt.Fprintln(w)

	// Packages
	fmt.Fprintf(w, "  \033[1mPackages\033[0m\n")
	fmt.Fprintf(w, "    Total installed: %d\n", r.Packages.Total)
	if len(r.Packages.ManuallySet) > 0 {
		fmt.Fprintf(w, "    Manually installed (%d): %s\n", len(r.Packages.ManuallySet), strings.Join(r.Packages.ManuallySet, ", "))
	}
	fmt.Fprintln(w)

	// Cron
	if len(r.Cron) > 0 {
		fmt.Fprintf(w, "  \033[1mCron Jobs\033[0m (%d)\n", len(r.Cron))
		for _, c := range r.Cron {
			fmt.Fprintf(w, "    [%s] %s %s\n", c.User, c.Schedule, c.Command)
		}
		fmt.Fprintln(w)
	}

	// Top processes
	fmt.Fprintf(w, "  \033[1mTop Processes\033[0m (by CPU)\n")
	fmt.Fprintf(w, "    %-10s %-6s %-5s %-5s %s\n", "USER", "PID", "CPU%", "MEM%", "COMMAND")
	limit := 10
	if len(r.Procs) < limit {
		limit = len(r.Procs)
	}
	for _, p := range r.Procs[:limit] {
		cmd := p.Cmd
		if len(cmd) > 50 {
			cmd = cmd[:50] + "..."
		}
		fmt.Fprintf(w, "    %-10s %-6s %-5s %-5s %s\n", p.User, p.PID, p.CPU, p.Mem, cmd)
	}
	fmt.Fprintln(w)

	// Recent files
	if len(r.Recent) > 0 {
		fmt.Fprintf(w, "  \033[1mRecently Modified Files\033[0m (last 7 days in /etc, /usr/bin, /usr/sbin)\n")
		for _, f := range r.Recent {
			fmt.Fprintf(w, "    %s  %s\n", f.ModTime, f.Path)
		}
		fmt.Fprintln(w)
	}
}
