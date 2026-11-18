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
	if len(normalized) != 2 { t.Fatalf("len = %d", len(normalized)) }
	if normalized[0].Severity != model.SeverityHigh || normalized[0].ID == "" { t.Fatalf("normalized = %#v", normalized) }
}

func TestScore(t *testing.T) {
	summary := Score([]model.Finding{{Severity: model.SeverityCritical, Asset: "host-a"}, {Severity: model.SeverityMedium, Asset: "host-b"}})
	if summary.Score != 5 || summary.Level != model.SeverityCritical { t.Fatalf("summary = %#v", summary) }
}
