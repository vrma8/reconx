package scoring

import (
	"testing"

	"github.com/vrma8/reconx/internal/model"
)

func TestNormalizeDeduplicatesAndSorts(t *testing.T) {
	findings := []model.Finding{
		{Severity: model.SeverityLow, Title: "Header", Asset: "a", Source: "test"},
		{Severity: model.SeverityLow, Title: "Header", Asset: "a", Source: "test"},
		{Severity: model.SeverityHigh, Title: "Secret", Asset: "b", Source: "test"},
	}
	normalized := Normalize(findings)
	if len(normalized) != 2 {
		t.Fatalf("len = %d", len(normalized))
	}
	if normalized[0].Severity != model.SeverityHigh || normalized[0].ID == "" {
		t.Fatalf("normalized = %#v", normalized)
	}
}

func TestScoreIncludesExploitabilityAndBusinessImpact(t *testing.T) {
	plain := Score([]model.Finding{{Severity: model.SeverityHigh, Asset: "host-a"}})
	rich := Score([]model.Finding{{Severity: model.SeverityHigh, Asset: "host-a", Exploitability: "high", BusinessImpact: "high"}})
	if rich.Score <= plain.Score || rich.HostScores["host-a"] <= plain.HostScores["host-a"] {
		t.Fatalf("plain=%#v rich=%#v", plain, rich)
	}
}

func TestScore(t *testing.T) {
	summary := Score([]model.Finding{{Severity: model.SeverityCritical, Asset: "host-a"}, {Severity: model.SeverityMedium, Asset: "host-b"}})
	if summary.Score != 5 || summary.Level != model.SeverityCritical {
		t.Fatalf("summary = %#v", summary)
	}
}

func TestAnnotateContextPreservesToolClassification(t *testing.T) {
	findings := AnnotateContext([]model.Finding{
		{Title: "Possible SQL injection in id", Source: "phase7-sqlmap", Exploitability: "unknown"},
		{Title: "External resource without Subresource Integrity", Source: "phase6-sri"},
		{Title: "Custom", Exploitability: "low", BusinessImpact: "high"},
	})
	if findings[0].Exploitability != "high" || findings[0].BusinessImpact != "high" {
		t.Fatalf("sqlmap context = %#v", findings[0])
	}
	if findings[1].Exploitability == "" || findings[1].BusinessImpact == "" {
		t.Fatalf("SRI context = %#v", findings[1])
	}
	if findings[2].Exploitability != "low" || findings[2].BusinessImpact != "high" {
		t.Fatalf("preserved context = %#v", findings[2])
	}
}
