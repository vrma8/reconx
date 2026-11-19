// Package scoring assigns stable finding identifiers, deduplicates evidence and
// produces an explainable, bounded target risk score.
package scoring

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"

	"github.com/vrma8/reconx/internal/model"
)

func Normalize(findings []model.Finding) []model.Finding {
	unique := make(map[string]model.Finding, len(findings))
	for _, finding := range findings {
		finding.ID = ID(finding)
		if existing, found := unique[finding.ID]; !found || severityWeight(finding.Severity) > severityWeight(existing.Severity) {
			unique[finding.ID] = finding
		}
	}
	output := make([]model.Finding, 0, len(unique))
	for _, finding := range unique {
		output = append(output, finding)
	}
	sort.Slice(output, func(i, j int) bool {
		left, right := severityWeight(output[i].Severity), severityWeight(output[j].Severity)
		if left != right {
			return left > right
		}
		if output[i].Asset != output[j].Asset {
			return output[i].Asset < output[j].Asset
		}
		return output[i].Title < output[j].Title
	})
	return output
}

func ID(finding model.Finding) string {
	stable := strings.Join([]string{string(finding.Severity), strings.ToLower(finding.Title), strings.ToLower(finding.Asset), strings.ToLower(finding.URL), finding.Evidence, finding.Source}, "\x00")
	digest := sha256.Sum256([]byte(stable))
	return "RX-" + strings.ToUpper(hex.EncodeToString(digest[:6]))
}

func Score(findings []model.Finding) model.RiskSummary {
	summary := model.RiskSummary{BySeverity: map[model.Severity]int{}, HostScores: map[string]int{}, TotalFindings: len(findings)}
	assets := map[string]struct{}{}
	for _, finding := range findings {
		summary.BySeverity[finding.Severity]++
		weight := adjustedWeight(finding)
		asset := finding.Asset
		if asset == "" {
			asset = "target"
		}
		summary.HostScores[asset] += weight
		if weight > 0 {
			assets[asset] = struct{}{}
		}
	}
	maximum := 0
	for _, score := range summary.HostScores {
		if score > maximum {
			maximum = score
		}
	}
	// A broad collection of independently affected assets raises the score,
	// while capping prevents a noisy report from exceeding 100.
	summary.Score = maximum + max(0, len(assets)-1)
	if summary.Score > 100 {
		summary.Score = 100
	}
	switch {
	case summary.BySeverity[model.SeverityCritical] > 0 || summary.Score >= 20:
		summary.Level = model.SeverityCritical
	case summary.BySeverity[model.SeverityHigh] > 0 || summary.Score >= 10:
		summary.Level = model.SeverityHigh
	case summary.BySeverity[model.SeverityMedium] > 0 || summary.Score >= 4:
		summary.Level = model.SeverityMedium
	case summary.BySeverity[model.SeverityLow] > 0:
		summary.Level = model.SeverityLow
	default:
		summary.Level = model.SeverityInfo
	}
	return summary
}

// AnnotateContext adds explainable exploitability and business-impact labels
// to findings that do not already provide them. Tool-specific classifications
// are always preserved; heuristics never downgrade a supplied value.
func AnnotateContext(findings []model.Finding) []model.Finding {
	output := append([]model.Finding(nil), findings...)
	for index, finding := range output {
		context := strings.ToLower(strings.Join([]string{finding.Title, finding.Description, finding.Evidence, finding.Source}, " "))
		if isUnclassified(finding.Exploitability) {
			output[index].Exploitability = exploitabilityHint(context)
		}
		if isUnclassified(finding.BusinessImpact) {
			output[index].BusinessImpact = businessImpactHint(context)
		}
	}
	return output
}

func isUnclassified(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "unknown":
		return true
	default:
		return false
	}
}

func exploitabilityHint(context string) string {
	for _, marker := range []string{"sql injection", "traversal", "auth bypass", "default credential", "secret", "sensitive path", "parameter reflection", "error pattern", "werkzeug", "exposed"} {
		if strings.Contains(context, marker) {
			return "high"
		}
	}
	for _, marker := range []string{"tls", "token", "cors", "cookie", "cve-"} {
		if strings.Contains(context, marker) {
			return "medium"
		}
	}
	return "low"
}

func businessImpactHint(context string) string {
	for _, marker := range []string{"sql injection", "secret", "token", "credential", "auth bypass", "traversal", "sensitive path", "exposed", "cve-"} {
		if strings.Contains(context, marker) {
			return "high"
		}
	}
	for _, marker := range []string{"tls", "xss", "reflection", "clickjacking", "cors", "cookie"} {
		if strings.Contains(context, marker) {
			return "medium"
		}
	}
	return "low"
}

// adjustedWeight adds explainable exploitability and business-impact bonuses
// to the base severity weight. Findings without this metadata keep the
// original weight, so historical reports remain comparable.
func adjustedWeight(finding model.Finding) int {
	weight := severityWeight(finding.Severity)
	if weight == 0 {
		return 0
	}
	switch strings.ToLower(finding.Exploitability) {
	case "high":
		weight += 2
	case "medium":
		weight++
	}
	switch strings.ToLower(finding.BusinessImpact) {
	case "high":
		weight += 2
	case "medium":
		weight++
	}
	if weight > 8 {
		return 8
	}
	return weight
}

func severityWeight(severity model.Severity) int {
	switch severity {
	case model.SeverityCritical:
		return 4
	case model.SeverityHigh:
		return 3
	case model.SeverityMedium:
		return 2
	case model.SeverityLow:
		return 1
	default:
		return 0
	}
}
func max(left, right int) int {
	if left > right {
		return left
	}
	return right
}
