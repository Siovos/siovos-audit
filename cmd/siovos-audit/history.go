package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/Siovos/siovos-audit/pkg/audit"
	"github.com/Siovos/siovos-audit/pkg/store"
)

func newHistoryCmd() *cobra.Command {
	var target string

	cmd := &cobra.Command{
		Use:   "history",
		Short: "Show audit history",
		RunE: func(cmd *cobra.Command, args []string) error {
			home, err := os.UserHomeDir()
			if err != nil {
				return err
			}
			dir := filepath.Join(home, ".siovos-audit", "history")
			s, err := store.NewFileStore(dir)
			if err != nil {
				return err
			}

			var summaries []audit.AuditSummary
			if target != "" {
				summaries, err = s.ListByTarget(target)
			} else {
				summaries, err = s.List()
			}
			if err != nil {
				return err
			}

			if len(summaries) == 0 {
				fmt.Println("No audit history found. Run an audit with --save to store results.")
				return nil
			}

			fmt.Printf("\n  %-40s %-8s %s\n", "Target", "Score", "Date")
			fmt.Printf("  %s\n", "────────────────────────────────────────────────────────────")
			for _, s := range summaries {
				fmt.Printf("  %-40s %3d/100  %s\n", s.Target, s.Score, s.Timestamp.Format("2006-01-02 15:04"))
			}
			fmt.Println()

			return nil
		},
	}

	cmd.Flags().StringVar(&target, "target", "", "Filter by target")

	return cmd
}
