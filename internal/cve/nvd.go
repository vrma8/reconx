// Package cve provides a bounded, offline matcher for local NVD JSON feeds.
package cve

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/vrma8/reconx/internal/model"
)

var versionPattern = regexp.MustCompile(`\b(?:[a-z][a-z0-9_-]*/)?([0-9]+(?:\.[0-9a-z_-]+){1,4})\b`)

type document struct {
	Vulnerabilities []struct {
		CVE entry `json:"cve"`
	} `json:"vulnerabilities"`
	Items []legacyItem `json:"CVE_Items"`
}

type entry struct {
	ID             string          `json:"id"`
	Descriptions   []description   `json:"descriptions"`
	Metrics        metrics         `json:"metrics"`
	Configurations []configuration `json:"configurations"`
}

type description struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type metrics struct {
	V31 []metricV3 `json:"cvssMetricV31"`
	V30 []metricV3 `json:"cvssMetricV30"`
	V2  []metricV2 `json:"cvssMetricV2"`
}

type metricV3 struct {
	Data cvssData `json:"cvssData"`
}

type metricV2 struct {
	Severity string `json:"baseSeverity"`
}

type cvssData struct {
	Severity string `json:"baseSeverity"`
}

type legacyItem struct {
	CVE struct {
		Meta struct {
			ID string `json:"ID"`
		} `json:"CVE_data_meta"`
		Description struct {
			Data []struct {
				Value string `json:"value"`
			} `json:"description_data"`
		} `json:"description"`
	} `json:"cve"`
	Configurations struct {
		Nodes []node `json:"nodes"`
	} `json:"configurations"`
	Impact struct {
		BaseMetricV3 struct {
			CVSSV3 cvssData `json:"cvssV3"`
		} `json:"baseMetricV3"`
	} `json:"impact"`
}

type configuration struct {
	Nodes []node `json:"nodes"`
}

type node struct {
	Matches  []cpe  `json:"cpeMatch"`
	Children []node `json:"nodes"`
}

type cpe struct {
	Criteria   string `json:"criteria"`
	URI        string `json:"cpe23Uri"`
	Vulnerable bool   `json:"vulnerable"`
}

// MatchFile supports NVD 2.0 and legacy NVD feeds. It only reports exact
// product/version CPE matches, favouring false negatives over speculative CVE
// assertions from an ambiguous banner.
func MatchFile(path string, services []model.Service) ([]model.Finding, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var feed document
	if err = json.Unmarshal(content, &feed); err != nil {
		return nil, fmt.Errorf("decode NVD feed: %w", err)
	}
	catalog := serviceCatalog(services)
	findings := make([]model.Finding, 0)
	for _, vulnerability := range feed.Vulnerabilities {
		if finding, matched := matchEntry(vulnerability.CVE, catalog); matched {
			findings = append(findings, finding)
		}
	}
	for _, item := range feed.Items {
		legacy := entry{
			ID:             item.CVE.Meta.ID,
			Configurations: []configuration{{Nodes: item.Configurations.Nodes}},
		}
		for _, itemDescription := range item.CVE.Description.Data {
			legacy.Descriptions = append(legacy.Descriptions, description{Lang: "en", Value: itemDescription.Value})
		}
		if severity := item.Impact.BaseMetricV3.CVSSV3.Severity; severity != "" {
			legacy.Metrics.V31 = []metricV3{{Data: cvssData{Severity: severity}}}
		}
		if finding, matched := matchEntry(legacy, catalog); matched {
			findings = append(findings, finding)
		}
	}
	return dedupe(findings), nil
}

type observedService struct {
	Asset   string
	Product string
	Version string
}

func serviceCatalog(services []model.Service) []observedService {
	values := make([]observedService, 0)
	for _, service := range services {
		text := strings.ToLower(service.Name + " " + service.Banner + " " + service.Version)
		match := versionPattern.FindStringSubmatch(text)
		if len(match) < 2 {
			continue
		}
		product := strings.ToLower(service.Name)
		for _, known := range []string{"nginx", "apache", "openssh", "postgresql", "mysql", "redis", "mongodb", "wordpress", "php", "elasticsearch"} {
			if strings.Contains(text, known) {
				product = known
				break
			}
		}
		values = append(values, observedService{Asset: service.Host, Product: product, Version: match[1]})
	}
	return values
}

func matchEntry(value entry, services []observedService) (model.Finding, bool) {
	if value.ID == "" {
		return model.Finding{}, false
	}
	for _, matchedCPE := range allCPE(value.Configurations) {
		product, version := parseCPE(matchedCPE.Criteria)
		if product == "" {
			product, version = parseCPE(matchedCPE.URI)
		}
		for _, service := range services {
			if product == service.Product && version == service.Version {
				return model.Finding{
					Severity:    severity(value),
					Title:       value.ID + " matches detected " + service.Product + " " + service.Version,
					Description: descriptionFor(value),
					Asset:       service.Asset,
					Evidence:    "CPE " + firstNonEmpty(matchedCPE.Criteria, matchedCPE.URI),
					Remediation: "Validate the installed version and apply the vendor security update or mitigation.",
					Confidence:  "version-match",
					Source:      "phase7-cve",
				}, true
			}
		}
	}
	return model.Finding{}, false
}

func allCPE(configurations []configuration) []cpe {
	values := make([]cpe, 0)
	var walk func([]node)
	walk = func(nodes []node) {
		for _, current := range nodes {
			for _, match := range current.Matches {
				if match.Vulnerable {
					values = append(values, match)
				}
			}
			walk(current.Children)
		}
	}
	for _, configuration := range configurations {
		walk(configuration.Nodes)
	}
	return values
}

func parseCPE(value string) (string, string) {
	parts := strings.Split(value, ":")
	if len(parts) < 6 {
		return "", ""
	}
	if parts[0] == "cpe" && parts[1] == "2.3" {
		return strings.ToLower(parts[4]), parts[5]
	}
	if strings.HasPrefix(value, "cpe:/") && len(parts) >= 5 {
		return strings.ToLower(parts[3]), parts[4]
	}
	return "", ""
}

func severity(value entry) model.Severity {
	if len(value.Metrics.V31) > 0 {
		return fromString(value.Metrics.V31[0].Data.Severity)
	}
	if len(value.Metrics.V30) > 0 {
		return fromString(value.Metrics.V30[0].Data.Severity)
	}
	if len(value.Metrics.V2) > 0 {
		return fromString(value.Metrics.V2[0].Severity)
	}
	return model.SeverityMedium
}

func fromString(value string) model.Severity {
	switch strings.ToLower(value) {
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

func descriptionFor(value entry) string {
	for _, item := range value.Descriptions {
		if item.Lang == "en" {
			return item.Value
		}
	}
	if len(value.Descriptions) > 0 {
		return value.Descriptions[0].Value
	}
	return "Local NVD feed match."
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func dedupe(values []model.Finding) []model.Finding {
	seen := map[string]struct{}{}
	output := make([]model.Finding, 0, len(values))
	for _, value := range values {
		key := value.Title + "\x00" + value.Asset
		if _, found := seen[key]; !found {
			seen[key] = struct{}{}
			output = append(output, value)
		}
	}
	sort.Slice(output, func(i, j int) bool { return output[i].Title < output[j].Title })
	return output
}
