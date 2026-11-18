package cve

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/vrma8/reconx/internal/model"
)

func TestMatchFileModernFeed(t *testing.T) {
	feed := `{"vulnerabilities":[{"cve":{"id":"CVE-2026-0001","descriptions":[{"lang":"en","value":"Test nginx issue"}],"metrics":{"cvssMetricV31":[{"cvssData":{"baseSeverity":"HIGH"}}]},"configurations":[{"nodes":[{"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:nginx:nginx:1.25.1:*:*:*:*:*:*:*"}]}]}]}}]}`
	path := filepath.Join(t.TempDir(), "nvd.json")
	if err := os.WriteFile(path, []byte(feed), 0o600); err != nil { t.Fatal(err) }
	findings, err := MatchFile(path, []model.Service{{Host:"192.0.2.1", Name:"http", Banner:"nginx/1.25.1"}})
	if err != nil { t.Fatal(err) }
	if len(findings) != 1 || findings[0].Severity != model.SeverityHigh { t.Fatalf("findings = %#v", findings) }
}
