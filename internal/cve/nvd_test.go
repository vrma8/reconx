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
	if err := os.WriteFile(path, []byte(feed), 0o600); err != nil {
		t.Fatal(err)
	}
	findings, err := MatchFile(path, []model.Service{{Host: "192.0.2.1", Name: "http", Banner: "nginx/1.25.1"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].Severity != model.SeverityHigh {
		t.Fatalf("findings = %#v", findings)
	}
}

func TestMatchFileVersionRanges(t *testing.T) {
	feed := `{"vulnerabilities":[{"cve":{"id":"CVE-2026-0002","descriptions":[{"lang":"en","value":"Range issue"}],"metrics":{"cvssMetricV31":[{"cvssData":{"baseSeverity":"CRITICAL"}}]},"configurations":[{"nodes":[{"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*:*","versionStartIncluding":"1.20","versionEndExcluding":"1.26"}]}]}]}}]}`
	path := filepath.Join(t.TempDir(), "nvd-range.json")
	if err := os.WriteFile(path, []byte(feed), 0o600); err != nil {
		t.Fatal(err)
	}
	findings, err := MatchFile(path, []model.Service{
		{Host: "192.0.2.1", Name: "http", Banner: "nginx/1.25.1"},
		{Host: "192.0.2.2", Name: "http", Banner: "nginx/1.27.0"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].Asset != "192.0.2.1" || findings[0].Confidence != "version-range" {
		t.Fatalf("range findings = %#v", findings)
	}
	if findings[0].BusinessImpact != "high" || len(findings[0].MITRE) == 0 {
		t.Fatalf("correlation metadata = %#v", findings[0])
	}
}

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		left, right string
		want        int
	}{
		{"1.25.1", "1.26", -1},
		{"1.26", "1.26", 0},
		{"1.26", "1.25.9", 1},
		{"8.0p1", "8.0", 1},
		{"2.4.0-rc1", "2.4.0", -1},
	}
	for _, tc := range cases {
		if got := compareVersions(tc.left, tc.right); got != tc.want {
			t.Errorf("compareVersions(%q,%q) = %d want %d", tc.left, tc.right, got, tc.want)
		}
	}
}
