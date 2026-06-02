package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/spf13/cobra"
)

func newUpdateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "update",
		Short: "Update siovos-audit to the latest version",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runUpdate()
		},
	}
}

type githubRelease struct {
	TagName string        `json:"tag_name"`
	Assets  []githubAsset `json:"assets"`
}

type githubAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

func runUpdate() error {
	fmt.Printf("Current version: %s\n", version)
	fmt.Println("Checking for updates...")

	latest, err := getLatestRelease()
	if err != nil {
		return fmt.Errorf("checking for updates: %w", err)
	}

	latestVersion := strings.TrimPrefix(latest.TagName, "v")
	currentVersion := strings.TrimPrefix(version, "v")

	if latestVersion == currentVersion {
		fmt.Println("Already up to date.")
		return nil
	}

	fmt.Printf("New version available: %s → %s\n", version, latest.TagName)

	// Find the right asset
	assetName := fmt.Sprintf("siovos-audit_%s_%s_%s.tar.gz", latestVersion, runtime.GOOS, runtime.GOARCH)
	var downloadURL string
	for _, asset := range latest.Assets {
		if asset.Name == assetName {
			downloadURL = asset.BrowserDownloadURL
			break
		}
	}

	if downloadURL == "" {
		return fmt.Errorf("no binary found for %s/%s in release %s.\nManual install: go install github.com/Siovos/siovos-audit/cmd/siovos-audit@latest", runtime.GOOS, runtime.GOARCH, latest.TagName)
	}

	fmt.Printf("Downloading %s...\n", assetName)

	// Download to temp
	resp, err := http.Get(downloadURL)
	if err != nil {
		return fmt.Errorf("downloading: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("download failed: HTTP %d", resp.StatusCode)
	}

	tmpFile, err := os.CreateTemp("", "siovos-audit-update-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmpFile.Name())

	if _, err := io.Copy(tmpFile, resp.Body); err != nil {
		tmpFile.Close()
		return err
	}
	tmpFile.Close()

	// Get current binary path
	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("finding current binary: %w", err)
	}
	execPath, err = filepath.EvalSymlinks(execPath)
	if err != nil {
		return err
	}

	fmt.Printf("Updated to %s\n", latest.TagName)
	fmt.Printf("Note: downloaded to %s\n", tmpFile.Name())
	fmt.Printf("To complete the update, extract and replace: tar xzf %s -C %s\n", tmpFile.Name(), filepath.Dir(execPath))

	return nil
}

func getLatestRelease() (*githubRelease, error) {
	resp, err := http.Get("https://api.github.com/repos/Siovos/siovos-audit/releases/latest")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		return nil, fmt.Errorf("no releases found. Create a release first: git tag v0.1.0 && git push --tags")
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("GitHub API returned %d", resp.StatusCode)
	}

	var release githubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return nil, err
	}
	return &release, nil
}

// CheckUpdateAvailable checks for a newer version and prints a message.
// Called after audit completes, non-blocking.
func CheckUpdateAvailable() {
	latest, err := getLatestRelease()
	if err != nil {
		return
	}
	latestVersion := strings.TrimPrefix(latest.TagName, "v")
	currentVersion := strings.TrimPrefix(version, "v")
	if latestVersion != currentVersion && currentVersion != "dev" {
		fmt.Fprintf(os.Stderr, "\n  \033[2mUpdate available: %s → %s (run: siovos-audit update)\033[0m\n", version, latest.TagName)
	}
}
