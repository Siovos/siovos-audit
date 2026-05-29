package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/Siovos/siovos-audit/pkg/audit"
	"github.com/Siovos/siovos-audit/pkg/collector"
	"github.com/Siovos/siovos-audit/pkg/reporter"
	"github.com/Siovos/siovos-audit/pkg/scoring"

	"github.com/Siovos/siovos-audit/internal/checks/firewall"
	"github.com/Siovos/siovos-audit/internal/checks/services"
	checkssh "github.com/Siovos/siovos-audit/internal/checks/ssh"
	"github.com/Siovos/siovos-audit/internal/checks/tls"
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
}

func newRunCmd() *cobra.Command {
	f := &runFlags{}

	cmd := &cobra.Command{
		Use:   "run",
		Short: "Run a security audit",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAudit(cmd.Context(), f)
		},
	}

	cmd.Flags().StringVar(&f.host, "host", "", "Target host")
	cmd.Flags().StringVar(&f.user, "user", "", "SSH user")
	cmd.Flags().IntVar(&f.port, "port", 22, "SSH port")
	cmd.Flags().StringVar(&f.keyPath, "key", "", "Path to SSH private key")
	cmd.Flags().BoolVar(&f.local, "local", false, "Audit the local machine")
	cmd.Flags().StringVar(&f.checks, "checks", "", "Comma-separated list of checks to run (e.g. ssh,firewall,tls)")
	cmd.Flags().StringVar(&f.format, "format", "terminal", "Output format: terminal, json")
	cmd.Flags().IntVar(&f.minScore, "min-score", 0, "Minimum acceptable score (exit code 1 if below)")

	return cmd
}

func runAudit(ctx context.Context, f *runFlags) error {
	col, err := createCollector(f)
	if err != nil {
		return err
	}
	defer col.Close()

	registry := audit.NewRegistry()
	registry.Register(checkssh.New())
	registry.Register(firewall.New())
	registry.Register(tls.New())
	registry.Register(services.New())

	scorer := scoring.NewDefaultScorer()
	engine := audit.NewEngine(registry, scorer)

	var checkIDs []string
	if f.checks != "" {
		checkIDs = strings.Split(f.checks, ",")
	}

	result, err := engine.Run(ctx, col, checkIDs)
	if err != nil {
		return err
	}

	rep, err := createReporter(f.format)
	if err != nil {
		return err
	}

	if err := rep.Report(result, os.Stdout); err != nil {
		return err
	}

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

func createReporter(format string) (reporter.Reporter, error) {
	switch format {
	case "terminal":
		return reporter.NewTerminalReporter(), nil
	case "json":
		return reporter.NewJSONReporter(true), nil
	default:
		return nil, fmt.Errorf("unknown format: %s", format)
	}
}
