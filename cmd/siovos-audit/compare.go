package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/Siovos/siovos-audit/pkg/audit"
	"github.com/Siovos/siovos-audit/pkg/collector"
	"github.com/Siovos/siovos-audit/pkg/scoring"

	"github.com/Siovos/siovos-audit/internal/checks/firewall"
	"github.com/Siovos/siovos-audit/internal/checks/kubernetes"
	"github.com/Siovos/siovos-audit/internal/checks/network"
	"github.com/Siovos/siovos-audit/internal/checks/services"
	checkssh "github.com/Siovos/siovos-audit/internal/checks/ssh"
	"github.com/Siovos/siovos-audit/internal/checks/system"
	"github.com/Siovos/siovos-audit/internal/checks/tls"
	"github.com/Siovos/siovos-audit/internal/checks/vpn"
)

type compareFlags struct {
	host1  string
	host2  string
	user   string
	port   int
	key    string
	checks string
}

func newCompareCmd() *cobra.Command {
	f := &compareFlags{}

	cmd := &cobra.Command{
		Use:   "compare",
		Short: "Compare security scores of two servers",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCompare(cmd.Context(), f)
		},
	}

	cmd.Flags().StringVar(&f.host1, "host1", "", "First server")
	cmd.Flags().StringVar(&f.host2, "host2", "", "Second server")
	cmd.Flags().StringVar(&f.user, "user", "", "SSH user (same for both)")
	cmd.Flags().IntVar(&f.port, "port", 22, "SSH port")
	cmd.Flags().StringVar(&f.key, "key", "", "SSH private key path")
	cmd.Flags().StringVar(&f.checks, "checks", "", "Checks to run")

	_ = cmd.MarkFlagRequired("host1")
	_ = cmd.MarkFlagRequired("host2")
	_ = cmd.MarkFlagRequired("user")

	return cmd
}

func runCompare(ctx context.Context, f *compareFlags) error {
	registry := defaultRegistry()
	scorer := scoring.NewDefaultScorer()
	engine := audit.NewEngine(registry, scorer)

	var checkIDs []string
	if f.checks != "" {
		checkIDs = strings.Split(f.checks, ",")
	}

	// Audit server 1
	col1, err := collector.NewSSHCollector(collector.SSHOptions{
		Host: f.host1, Port: f.port, User: f.user, KeyPath: f.key,
	})
	if err != nil {
		return fmt.Errorf("connecting to %s: %w", f.host1, err)
	}
	result1, err := engine.Run(ctx, col1, checkIDs)
	col1.Close()
	if err != nil {
		return err
	}

	// Audit server 2
	col2, err := collector.NewSSHCollector(collector.SSHOptions{
		Host: f.host2, Port: f.port, User: f.user, KeyPath: f.key,
	})
	if err != nil {
		return fmt.Errorf("connecting to %s: %w", f.host2, err)
	}
	result2, err := engine.Run(ctx, col2, checkIDs)
	col2.Close()
	if err != nil {
		return err
	}

	printComparison(result1, result2)
	return nil
}

func printComparison(r1, r2 *audit.AuditResult) {
	w := os.Stdout

	fmt.Fprintf(w, "\n  \033[1mServer Comparison\033[0m\n\n")
	fmt.Fprintf(w, "  %-30s %s\n", r1.Target, r2.Target)
	fmt.Fprintf(w, "  %s\n\n", strings.Repeat("-", 60))

	// Collect all categories
	cats := make(map[string]bool)
	for k := range r1.Score.Categories {
		cats[k] = true
	}
	for k := range r2.Score.Categories {
		cats[k] = true
	}

	for cat := range cats {
		s1 := r1.Score.Categories[cat].Score
		s2 := r2.Score.Categories[cat].Score
		diff := s2 - s1

		diffStr := ""
		if diff > 0 {
			diffStr = fmt.Sprintf("\033[32m+%d\033[0m", diff)
		} else if diff < 0 {
			diffStr = fmt.Sprintf("\033[31m%d\033[0m", diff)
		} else {
			diffStr = "="
		}

		fmt.Fprintf(w, "  %-20s %3d/100    %3d/100    %s\n", cat, s1, s2, diffStr)
	}

	fmt.Fprintf(w, "\n  %-20s %s%3d/100\033[0m    %s%3d/100\033[0m\n\n",
		"OVERALL",
		scoreColor(r1.Score.Overall), r1.Score.Overall,
		scoreColor(r2.Score.Overall), r2.Score.Overall,
	)
}

func scoreColor(score int) string {
	switch {
	case score >= 80:
		return "\033[32m"
	case score >= 60:
		return "\033[33m"
	default:
		return "\033[31m"
	}
}

func defaultRegistry() *audit.Registry {
	r := audit.NewRegistry()
	r.Register(checkssh.New())
	r.Register(firewall.New())
	r.Register(tls.New())
	r.Register(services.New())
	r.Register(kubernetes.New())
	r.Register(vpn.New())
	r.Register(system.New())
	r.Register(network.New())
	return r
}
