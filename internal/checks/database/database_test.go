package database_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/Siovos/siovos-audit/internal/checks/database"
	"github.com/Siovos/siovos-audit/pkg/audit"
	"github.com/Siovos/siovos-audit/pkg/collector"
)

type mockCollector struct {
	commands map[string]string
}

func (m *mockCollector) Exec(_ context.Context, cmd string) ([]byte, error) {
	if out, ok := m.commands[cmd]; ok {
		return []byte(out), nil
	}
	return nil, fmt.Errorf("not found")
}
func (m *mockCollector) ReadFile(_ context.Context, _ string) ([]byte, error) {
	return nil, fmt.Errorf("not found")
}
func (m *mockCollector) Platform() collector.Platform { return collector.Platform{OS: "linux"} }
func (m *mockCollector) Target() string               { return "test" }
func (m *mockCollector) Close() error                  { return nil }

func TestDatabase_NoDatabases(t *testing.T) {
	col := &mockCollector{commands: map[string]string{}}

	c := database.New()
	findings, err := c.Run(context.Background(), col)
	if err != nil {
		t.Fatal(err)
	}

	if len(findings) != 1 || findings[0].ID != "db-none" {
		t.Error("no databases should return single info finding")
	}
}

func TestDatabase_RedisNoPassword(t *testing.T) {
	col := &mockCollector{commands: map[string]string{
		"pgrep -x redis-server 2>/dev/null": "1234",
		"grep -E '^\\s*bind' /etc/redis/redis.conf 2>/dev/null || grep -E '^\\s*bind' /etc/redis.conf 2>/dev/null": "bind 127.0.0.1",
	}}

	c := database.New()
	findings, err := c.Run(context.Background(), col)
	if err != nil {
		t.Fatal(err)
	}

	hasWarn := false
	for _, f := range findings {
		if f.ID == "db-redis-auth" && f.Severity == audit.SeverityWarn {
			hasWarn = true
		}
	}
	if !hasWarn {
		t.Error("Redis without password should be WARN")
	}
}
