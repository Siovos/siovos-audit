package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/Siovos/siovos-audit/pkg/audit"
	"github.com/Siovos/siovos-audit/pkg/collector"
	"github.com/Siovos/siovos-audit/pkg/compliance"
	"github.com/Siovos/siovos-audit/pkg/explain"
	"github.com/Siovos/siovos-audit/pkg/reporter"
	"github.com/Siovos/siovos-audit/pkg/scoring"
	"github.com/Siovos/siovos-audit/pkg/store"
)

type runFlags struct {
	host     string
	user     string
	port     int
	keyPath  string
	local    bool
	checks   string
	format   string
	minScore int
	config   string
	save        bool
	profile     string
	expectPorts string
	explainMode bool
	compliance  string
}

func newRunCmd() *cobra.Command {
	f := &runFlags{}

	cmd := &cobra.Command{
		Use:   "run",
		Short: "Run a security audit",
		Long:  "Run a security audit. Without --host or --local, launches interactive mode.",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Interactive mode if no target specified
			if f.host == "" && !f.local {
				return runInteractiveMode(cmd.Context())
			}
			return runAudit(cmd.Context(), f)
		},
	}

	cmd.Flags().StringVar(&f.host, "host", "", "Target host")
	cmd.Flags().StringVar(&f.user, "user", "", "SSH user")
	cmd.Flags().IntVar(&f.port, "port", 22, "SSH port")
	cmd.Flags().StringVar(&f.keyPath, "key", "", "Path to SSH private key")
	cmd.Flags().BoolVar(&f.local, "local", false, "Audit the local machine")
	cmd.Flags().StringVar(&f.checks, "checks", "", "Comma-separated list of checks (e.g. ssh,firewall,tls)")
	cmd.Flags().StringVar(&f.format, "format", "terminal", "Output format: terminal, json, html")
	cmd.Flags().IntVar(&f.minScore, "min-score", 0, "Minimum acceptable score (exit code 1 if below)")
	cmd.Flags().StringVar(&f.config, "config", ".siovos-audit.yml", "Path to config file")
	cmd.Flags().BoolVar(&f.save, "save", false, "Save result to history")
	cmd.Flags().StringVar(&f.profile, "profile", "", "Server profile: minimal-vps, web-server, kubernetes-node, database-server, vpn-gateway, full")
	cmd.Flags().StringVar(&f.expectPorts, "expect-ports", "", "Additional expected ports, comma-separated (e.g. 9100,9090,3000)")
	cmd.Flags().BoolVar(&f.explainMode, "explain", false, "Add detailed explanations to findings (why it matters, risk, how to fix)")
	cmd.Flags().StringVar(&f.compliance, "compliance", "", "Show compliance mapping: cis-level1, soc2-basic")

	return cmd
}

func runInteractiveMode(ctx context.Context) error {
	result, err := runInteractive()
	if err != nil {
		return err
	}
	return runAudit(ctx, interactiveToFlags(result))
}

func runAudit(ctx context.Context, f *runFlags) error {
	col, err := createCollector(f)
	if err != nil {
		return err
	}
	defer col.Close()

	// Load config
	cfg, err := audit.LoadConfig(f.config)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	// Add --expect-ports to config (before profile merge so they get included)
	if f.expectPorts != "" {
		for _, p := range strings.Split(f.expectPorts, ",") {
			p = strings.TrimSpace(p)
			if p != "" {
				cfg.ExpectedPorts = append(cfg.ExpectedPorts, p)
			}
		}
	}

	// Apply profile (from flag or config file) — merges on top of config ports
	profileID := f.profile
	if profileID == "" {
		profileID = cfg.Profile
	}
	if profileID != "" {
		cfg.ApplyProfile(profileID)
	}

	registry := defaultRegistry()
	scorer := scoring.NewDefaultScorer()
	engine := audit.NewEngine(registry, scorer)

	var checkIDs []string
	if f.checks != "" {
		checkIDs = strings.Split(f.checks, ",")
	} else if profileID != "" {
		if p, ok := audit.Profiles[profileID]; ok && p.Checks != nil {
			checkIDs = p.Checks
		}
	}

	result, err := engine.Run(ctx, col, checkIDs)
	if err != nil {
		return err
	}

	result.Findings = cfg.FilterFindings(result.Findings)
	if f.explainMode {
		result.Findings = explain.Enrich(result.Findings)
	}
	result.Score = scorer.Score(result.Findings)

	rep, err := createReporter(f.format)
	if err != nil {
		return err
	}

	if err := rep.Report(result, os.Stdout); err != nil {
		return err
	}

	if f.compliance != "" {
		printCompliance(f.compliance, result)
	}

	if f.save {
		home, _ := os.UserHomeDir()
		dir := filepath.Join(home, ".siovos-audit", "history")
		if s, err := store.NewFileStore(dir); err == nil {
			_ = s.Save(result)
		}
	}

	// Non-blocking update check
	go CheckUpdateAvailable()

	if f.minScore > 0 && result.Score.Overall < f.minScore {
		return fmt.Errorf("score %d is below minimum %d", result.Score.Overall, f.minScore)
	}

	return nil
}

func createCollector(f *runFlags) (collector.Collector, error) {
	if f.local {
		return collector.NewLocalCollector()
	}
	if f.host == "" {
		return nil, fmt.Errorf("either --host or --local is required")
	}
	return collector.NewSSHCollector(collector.SSHOptions{
		Host:    f.host,
		Port:    f.port,
		User:    f.user,
		KeyPath: f.keyPath,
	})
}

func printCompliance(frameworkID string, result *audit.AuditResult) {
	fw, ok := compliance.Frameworks[frameworkID]
	if !ok {
		fmt.Fprintf(os.Stderr, "Unknown compliance framework: %s\n", frameworkID)
		return
	}

	findingsByID := make(map[string]audit.Finding)
	for _, f := range result.Findings {
		findingsByID[f.ID] = f
	}

	fmt.Printf("\n  \033[1m%s Compliance\033[0m\n", fw.Name)
	fmt.Printf("  %s\n\n", fw.Description)

	passed := 0
	total := len(fw.Controls)

	for _, ctrl := range fw.Controls {
		allPass := true
		for _, fid := range ctrl.FindingIDs {
			if f, ok := findingsByID[fid]; ok {
				if f.Severity >= audit.SeverityFail {
					allPass = false
					break
				}
			}
		}

		status := "\033[32mPASS\033[0m"
		if !allPass {
			status = "\033[31mFAIL\033[0m"
		} else {
			passed++
		}
		name := ctrl.Name
		if ctrl.Description != "" {
			name = ctrl.Name + " — " + ctrl.Description
		}
		fmt.Printf("  [%s] %s: %s\n", status, ctrl.ID, name)
	}

	pct := 0
	if total > 0 {
		pct = passed * 100 / total
	}
	fmt.Printf("\n  Compliance: %d/%d controls passed (%d%%)\n\n", passed, total, pct)
}

func createReporter(format string) (reporter.Reporter, error) {
	switch format {
	case "terminal":
		return reporter.NewTerminalReporter(), nil
	case "json":
		return reporter.NewJSONReporter(true), nil
	case "html":
		return reporter.NewHTMLReporter(), nil
	default:
		return nil, fmt.Errorf("unknown format: %s", format)
	}
}
