package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Siovos/siovos-audit/pkg/audit"
)

// FileStore persists audit results as JSON files in a directory.
type FileStore struct {
	dir string
}

func NewFileStore(dir string) (*FileStore, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("creating store directory: %w", err)
	}
	return &FileStore{dir: dir}, nil
}

func (s *FileStore) Save(result *audit.AuditResult) error {
	id := fmt.Sprintf("%s_%s", sanitize(result.Target), result.FinishedAt.Format("20060102-150405"))
	path := filepath.Join(s.dir, id+".json")

	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func (s *FileStore) Load(id string) (*audit.AuditResult, error) {
	path := filepath.Join(s.dir, id+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var result audit.AuditResult
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

func (s *FileStore) List() ([]audit.AuditSummary, error) {
	return s.listFiles("")
}

func (s *FileStore) ListByTarget(target string) ([]audit.AuditSummary, error) {
	return s.listFiles(sanitize(target))
}

func (s *FileStore) listFiles(prefix string) ([]audit.AuditSummary, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, err
	}

	var summaries []audit.AuditSummary
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		if prefix != "" && !strings.HasPrefix(entry.Name(), prefix) {
			continue
		}

		id := strings.TrimSuffix(entry.Name(), ".json")
		result, err := s.Load(id)
		if err != nil {
			continue
		}
		summaries = append(summaries, audit.AuditSummary{
			ID:        id,
			Target:    result.Target,
			Score:     result.Score.Overall,
			Timestamp: result.FinishedAt,
		})
	}

	sort.Slice(summaries, func(i, j int) bool {
		return summaries[i].Timestamp.After(summaries[j].Timestamp)
	})

	return summaries, nil
}

func sanitize(s string) string {
	r := strings.NewReplacer(" ", "-", "/", "-", ":", "-", ".", "-")
	return strings.ToLower(r.Replace(s))
}
