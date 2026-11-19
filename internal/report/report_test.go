package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vrma8/reconx/internal/model"
)

func TestHTMLIsInteractiveAndEmbedsScreenshots(t *testing.T) {
	directory := t.TempDir()
	imagePath := filepath.Join(directory, "shot.png")
	if err := os.WriteFile(imagePath, []byte("PNGFAKE"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "report.html")
	value := model.Report{
		Target:      model.TargetProfile{Input: "example.test"},
		Findings:    []model.Finding{{ID: "RX-1", Severity: model.SeverityHigh, Title: "Test finding", Evidence: "evidence"}},
		Screenshots: []model.ScreenshotRef{{URL: "https://example.test", Path: imagePath, Name: "shot.png"}},
	}
	if err := HTML(path, value); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	html := string(content)
	for _, marker := range []string{"filterFindings()", "<details", "data:image/png;base64,", "Test finding"} {
		if !strings.Contains(html, marker) {
			t.Fatalf("HTML missing %q", marker)
		}
	}
}

func TestCSVIncludesScoringMetadata(t *testing.T) {
	path := filepath.Join(t.TempDir(), "findings.csv")
	if err := CSV(path, []model.Finding{{ID: "RX-1", Severity: model.SeverityHigh, Title: "Finding", Exploitability: "high", BusinessImpact: "medium"}}); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), "exploitability,business_impact") || !strings.Contains(string(content), "RX-1,high,Finding") {
		t.Fatalf("csv = %q", content)
	}
}
