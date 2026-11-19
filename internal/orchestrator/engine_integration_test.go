package orchestrator

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vrma8/reconx/internal/config"
)

// TestLocalRunProducesUsableWorkspace exercises the intake, port, web,
// secrets, scoring and reporting phases against an in-process HTTP target.
// No external scanner, API key, or root privilege is required.
func TestLocalRunProducesUsableWorkspace(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "text/html")
		_, _ = writer.Write([]byte(`<html><title>Local fixture</title><script>const apiKey = "AKIA1234567890ABCDEF";</script></html>`))
	}))
	defer server.Close()

	settings := config.Default()
	settings.Authorized = true
	settings.Workspace = filepath.Join(t.TempDir(), "workspace")
	settings.Phases = "0,4,6,8,9,10"
	settings.Fast = true
	settings.Rate = 10000
	settings.Timeout = 500 * time.Millisecond
	settings.Workers = 4
	settings.Retries = 0
	settings.OSINT = false
	settings.SubdomainBrute = false
	settings.SubdomainPermutations = false
	settings.CloudAssets = false
	settings.TakeoverVerify = false
	settings.CrawlDepth = 0
	settings.APIDiscovery = false
	settings.NLP = false
	settings.Quiet = true

	engine, err := New(server.URL, settings, slog.New(slog.NewTextHandler(os.Stderr, nil)))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	reportValue, err := engine.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if reportValue.Risk.TotalFindings == 0 {
		t.Fatal("expected findings from the local web fixture")
	}
	var reportedPhase10 bool
	for _, phase := range reportValue.Phases {
		if phase.Number == 10 {
			reportedPhase10 = true
		}
	}
	if !reportedPhase10 {
		t.Fatalf("final report omitted phase 10: %#v", reportValue.Phases)
	}
	var secretFinding bool
	for _, finding := range reportValue.Findings {
		if finding.Source == "phase8-secrets" && strings.Contains(finding.Title, "AWS access key ID") {
			secretFinding = true
		}
		if strings.Contains(finding.Evidence, "AKIA1234567890ABCDEF") {
			t.Fatal("secret evidence must be redacted by default")
		}
	}
	if !secretFinding {
		t.Fatalf("expected a redacted secret finding, got %#v", reportValue.Findings)
	}
	for _, relative := range []string{
		"target_profile.json", "04_ports/ports.json", "06_web/web_results.json",
		"08_secrets/secrets.json", "09_report/report.json", "09_report/report.html",
		"09_report/findings.csv", "09_report/risk_scores.json",
	} {
		if _, err := os.Stat(engine.Workspace.Path(relative)); err != nil {
			t.Fatalf("missing workspace artifact %s: %v", relative, err)
		}
	}
}
