// Package external normalizes machine-readable output from optional tools.
package external

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/vrma8/reconx/internal/model"
)

type nucleiRecord struct {
	TemplateID       string   `json:"template-id"`
	Template         string   `json:"template"`
	MatchedAt        string   `json:"matched-at"`
	Host             string   `json:"host"`
	MatcherName      string   `json:"matcher-name"`
	ExtractedResults []string `json:"extracted-results"`
	Info             struct {
		Name        string   `json:"name"`
		Description string   `json:"description"`
		Severity    string   `json:"severity"`
		Reference   []string `json:"reference"`
	} `json:"info"`
}

// ParseNucleiJSONL turns Nuclei's documented JSONL output into unverified,
// normalized findings. It never treats malformed records as findings and keeps
// evidence bounded so a tool cannot create an unbounded report.
func ParseNucleiJSONL(reader io.Reader) ([]model.Finding, error) {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 64*1024), 2*1024*1024)
	findings := make([]model.Finding, 0)
	line := 0
	for scanner.Scan() {
		line++
		value := strings.TrimSpace(scanner.Text())
		if value == "" {
			continue
		}
		var record nucleiRecord
		if err := json.Unmarshal([]byte(value), &record); err != nil {
			return nil, fmt.Errorf("nuclei JSONL line %d: %w", line, err)
		}
		severity := nucleiSeverity(record.Info.Severity)
		title := strings.TrimSpace(record.Info.Name)
		if title == "" {
			title = strings.TrimSpace(record.TemplateID)
		}
		if title == "" {
			title = strings.TrimSpace(record.Template)
		}
		if title == "" {
			return nil, fmt.Errorf("nuclei JSONL line %d: missing template name", line)
		}
		asset := record.Host
		if asset == "" {
			asset = record.MatchedAt
		}
		evidence := strings.TrimSpace(record.MatcherName)
		if len(record.ExtractedResults) > 0 {
			evidence = joinBounded(record.ExtractedResults, 3, 500)
		}
		findings = append(findings, model.Finding{
			Severity: severity, Title: title, Description: strings.TrimSpace(record.Info.Description),
			Asset: asset, URL: record.MatchedAt, Evidence: evidence, Remediation: "Validate this external scanner result, then remediate according to the affected product guidance.",
			Confidence: "tool-reported", Source: "phase7-nuclei",
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return findings, nil
}

func nucleiSeverity(value string) model.Severity {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "critical":
		return model.SeverityCritical
	case "high":
		return model.SeverityHigh
	case "medium":
		return model.SeverityMedium
	case "low":
		return model.SeverityLow
	default:
		return model.SeverityInfo
	}
}

func joinBounded(values []string, maximum, limit int) string {
	output := make([]string, 0, maximum)
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			output = append(output, value)
		}
		if len(output) == maximum {
			break
		}
	}
	joined := strings.Join(output, "; ")
	if len(joined) > limit {
		return joined[:limit]
	}
	return joined
}
