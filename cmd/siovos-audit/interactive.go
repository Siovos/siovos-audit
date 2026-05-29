package main

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/huh"

	"github.com/Siovos/siovos-audit/pkg/audit"
)

type interactiveResult struct {
	host           string
	user           string
	port           int
	keyPath        string
	local          bool
	profileID      string
	selectedChecks []string
	expectPorts    string
	format         string
}

func runInteractive() (*interactiveResult, error) {
	r := &interactiveResult{port: 22}

	// Step 1: Connection
	var connType string
	err := huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[string]().
				Title("How do you want to connect?").
				Options(
					huh.NewOption("Remote server (SSH)", "ssh"),
					huh.NewOption("Local machine", "local"),
				).
				Value(&connType),
		),
	).Run()
	if err != nil {
		return nil, err
	}

	if connType == "local" {
		r.local = true
	} else {
		err = huh.NewForm(
			huh.NewGroup(
				huh.NewInput().
					Title("Host (IP or hostname)").
					Value(&r.host),
				huh.NewInput().
					Title("SSH user").
					Value(&r.user),
				huh.NewInput().
					Title("SSH key path (leave empty for default)").
					Value(&r.keyPath),
			),
		).Run()
		if err != nil {
			return nil, err
		}
	}

	// Step 2: Profile selection
	profileOptions := []huh.Option[string]{}
	for _, p := range audit.ProfileList() {
		label := fmt.Sprintf("%s — %s", p.Name, p.Description)
		profileOptions = append(profileOptions, huh.NewOption(label, p.ID))
	}

	err = huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[string]().
				Title("Choose a profile").
				Description("Profiles set expected ports and enable relevant checks").
				Options(profileOptions...).
				Value(&r.profileID),
		),
	).Run()
	if err != nil {
		return nil, err
	}

	// Step 3: Show what the profile expects and ask for additions
	profile := audit.Profiles[r.profileID]
	portsHint := "none"
	if len(profile.ExpectedPorts) > 0 {
		portsHint = strings.Join(profile.ExpectedPorts, ", ")
	}

	err = huh.NewForm(
		huh.NewGroup(
			huh.NewInput().
				Title("Additional expected ports").
				Description(fmt.Sprintf("Profile already expects: %s\nAdd more ports comma-separated, or leave empty", portsHint)).
				Placeholder("e.g. 9100,9090,3000").
				Value(&r.expectPorts),
		),
	).Run()
	if err != nil {
		return nil, err
	}

	// Step 4: Check selection (pre-filled from profile)
	allChecks := []string{"ssh", "firewall", "tls", "services", "system", "network", "kubernetes", "vpn"}

	preselected := make(map[string]bool)
	if profile.Checks != nil {
		for _, c := range profile.Checks {
			preselected[c] = true
		}
	} else {
		for _, c := range allChecks {
			preselected[c] = true
		}
	}

	checkOptions := []huh.Option[string]{}
	for _, c := range allChecks {
		checkOptions = append(checkOptions, huh.NewOption(c, c).Selected(preselected[c]))
	}

	err = huh.NewForm(
		huh.NewGroup(
			huh.NewMultiSelect[string]().
				Title("Which checks to run?").
				Options(checkOptions...).
				Value(&r.selectedChecks),
		),
	).Run()
	if err != nil {
		return nil, err
	}

	// Step 5: Output format
	err = huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[string]().
				Title("Output format").
				Options(
					huh.NewOption("Terminal (colored)", "terminal"),
					huh.NewOption("JSON", "json"),
					huh.NewOption("HTML report", "html"),
				).
				Value(&r.format),
		),
	).Run()
	if err != nil {
		return nil, err
	}

	return r, nil
}

func interactiveToFlags(r *interactiveResult) *runFlags {
	return &runFlags{
		host:        r.host,
		user:        r.user,
		port:        r.port,
		keyPath:     r.keyPath,
		local:       r.local,
		checks:      strings.Join(r.selectedChecks, ","),
		format:      r.format,
		config:      ".siovos-audit.yml",
		profile:     r.profileID,
		expectPorts: r.expectPorts,
	}
}
