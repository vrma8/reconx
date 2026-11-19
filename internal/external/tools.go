package external

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"

	"github.com/vrma8/reconx/internal/model"
)

type niktoDocument struct {
	Host            string `json:"host"`
	Port            string `json:"port"`
	Vulnerabilities []struct {
		ID       string `json:"id"`
		URL      string `json:"url"`
		Method   string `json:"method"`
		Message  string `json:"msg"`
		Severity string `json:"severity"`
	} `json:"vulnerabilities"`
}

// ParseNiktoJSON normalizes Nikto's documented JSON report. Entries remain
// tool-reported until a human validates them.
func ParseNiktoJSON(reader io.Reader) ([]model.Finding, error) {
	var document niktoDocument
	if err := json.NewDecoder(reader).Decode(&document); err != nil {
		return nil, fmt.Errorf("decode Nikto JSON: %w", err)
	}
	findings := make([]model.Finding, 0, len(document.Vulnerabilities))
	for _, entry := range document.Vulnerabilities {
		title := strings.TrimSpace(entry.Message)
		if title == "" {
			title = "Nikto reported " + entry.ID
		}
		findings = append(findings, model.Finding{
			Severity: scannerSeverity(entry.Severity), Title: bounded(title, 300),
			Description: "Nikto reported this item; validate it before remediation or disclosure.",
			Asset:       document.Host, URL: entry.URL, Evidence: entry.Method + " " + entry.ID,
			MITRE: []string{"T1190"}, Remediation: "Validate the Nikto result and apply the product-specific mitigation.",
			Confidence: "tool-reported", Source: "phase7-nikto", Exploitability: "unknown", BusinessImpact: "unknown",
		})
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Title < findings[j].Title })
	return findings, nil
}

func scannerSeverity(value string) model.Severity {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "high", "critical":
		return model.SeverityHigh
	case "medium":
		return model.SeverityMedium
	case "low", "info", "informational":
		return model.SeverityLow
	default:
		return model.SeverityInfo
	}
}

func bounded(value string, limit int) string {
	value = strings.TrimSpace(value)
	if len(value) > limit {
		return value[:limit]
	}
	return value
}

var cvePattern = regexp.MustCompile(`CVE-\d{4}-\d{4,}`)

// ParseWPScanJSON extracts confirmed CVE/plugin identifiers from WPScan's JSON
// report without trusting arbitrary tool text as executable content.
func ParseWPScanJSON(reader io.Reader, target string) ([]model.Finding, error) {
	var document any
	if err := json.NewDecoder(reader).Decode(&document); err != nil {
		return nil, fmt.Errorf("decode WPScan JSON: %w", err)
	}
	findings := make([]model.Finding, 0)
	seen := map[string]struct{}{}
	var walk func(value any, path string)
	walk = func(value any, path string) {
		if len(findings) >= 200 {
			return
		}
		switch typed := value.(type) {
		case map[string]any:
			name, _ := typed["name"].(string)
			if name == "" && path != "" {
				parts := strings.Split(path, ".")
				name = parts[len(parts)-1]
			}
			for key, child := range typed {
				walk(child, strings.TrimPrefix(path+"."+key, "."))
			}
			for _, identifier := range cvePattern.FindAllString(fmt.Sprint(typed), -1) {
				key := identifier + "\x00" + path
				if _, found := seen[key]; found {
					continue
				}
				seen[key] = struct{}{}
				findings = append(findings, model.Finding{
					Severity: model.SeverityHigh, Title: identifier + " in WordPress component " + name,
					Description: "WPScan associated this CVE with a detected WordPress component.",
					Asset:       target, URL: target, Evidence: identifier + " from " + path,
					MITRE: []string{"T1190"}, Remediation: "Update or remove the affected WordPress component.",
					Confidence: "tool-reported", Source: "phase7-wpscan", Exploitability: "unknown", BusinessImpact: "high",
				})
			}
		case []any:
			for index, child := range typed {
				walk(child, fmt.Sprintf("%s.%d", path, index))
			}
		}
	}
	walk(document, "")
	sort.Slice(findings, func(i, j int) bool { return findings[i].Title < findings[j].Title })
	return findings, nil
}

var (
	sqlmapParameter = regexp.MustCompile(`(?i)^\[?\s*Parameter:\s*([^\s\]]+)`)
	sqlmapType      = regexp.MustCompile(`(?i)^\[?\s*Type:\s*(.+)$`)
	sqlmapTitle     = regexp.MustCompile(`(?i)^\[?\s*Title:\s*(.+)$`)
)

// ParseSQLMapOutput extracts injection types from sqlmap's console output.
// It never executes or replays anything found in the report.
func ParseSQLMapOutput(reader io.Reader, target string) ([]model.Finding, error) {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 64*1024), 2*1024*1024)
	findings := make([]model.Finding, 0)
	parameter := ""
	injectionType := ""
	flush := func() {
		if parameter == "" || injectionType == "" {
			return
		}
		findings = append(findings, model.Finding{
			Severity: model.SeverityCritical, Title: "Possible SQL injection in " + parameter,
			Description: "sqlmap reported an injection type for this parameter. Confirm manually before remediation.",
			Asset:       target, URL: target, Evidence: bounded(injectionType, 300),
			MITRE: []string{"T1190"}, Remediation: "Use parameterized queries and validate the finding manually.",
			Confidence: "tool-reported", Source: "phase7-sqlmap", Exploitability: "high", BusinessImpact: "high",
		})
		parameter, injectionType = "", ""
	}
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if match := sqlmapParameter.FindStringSubmatch(line); len(match) > 1 {
			flush()
			parameter = match[1]
		}
		if match := sqlmapType.FindStringSubmatch(line); len(match) > 1 {
			injectionType = strings.Trim(match[1], "[]* ")
		}
		if match := sqlmapTitle.FindStringSubmatch(line); len(match) > 1 && injectionType == "" {
			injectionType = strings.Trim(match[1], "[]* ")
		}
		if len(findings) >= 100 {
			break
		}
	}
	flush()
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Title < findings[j].Title })
	return findings, nil
}
