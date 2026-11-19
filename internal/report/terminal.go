package report

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/vrma8/reconx/internal/model"
)

// Terminal writes a concise, deterministic executive summary. ANSI colour is
// intentionally opt-in so redirected output remains machine-friendly.
func Terminal(writer io.Writer, value model.Report, colour bool) {
	TerminalDetailed(writer, value, colour, false)
}

// TerminalDetailed adds per-section detail and activity counters to the
// executive summary. Long lists are capped so interactive terminals stay
// readable; complete data remains in the workspace artifacts.
func TerminalDetailed(writer io.Writer, value model.Report, colour, detailed bool) {
	level := strings.ToUpper(string(value.Risk.Level))
	fmt.Fprintln(writer, "\nRECONX — authorized reconnaissance summary")
	fmt.Fprintf(writer, "Target: %s\nRisk: %s (%d/100)\nFindings: %d\nHosts: %d\n", value.Target.Input, paint(level, value.Risk.Level, colour), value.Risk.Score, value.Risk.TotalFindings, len(value.Hosts))
	fmt.Fprintf(writer, "Activity: %d probes, %d HTTP requests, %d DNS queries, %d tool invocations, %d screenshots\n", value.Stats.Probes, value.Stats.HTTPRequests, value.Stats.DNSQueries, value.Stats.ToolInvocations, len(value.Screenshots))
	if detailed {
		writeDetailedSections(writer, value)
	}
	if len(value.Phases) > 0 {
		fmt.Fprintln(writer, "\nPhases:")
		for _, phase := range value.Phases {
			fmt.Fprintf(writer, "  [%02d] %-24s %s (%s)\n", phase.Number, phase.Name, strings.ToUpper(phase.Status), phase.Duration.Round(1e6))
		}
	}
	if len(value.Findings) == 0 {
		return
	}
	findings := append([]model.Finding(nil), value.Findings...)
	sort.SliceStable(findings, func(i, j int) bool {
		left, right := severityRank(findings[i].Severity), severityRank(findings[j].Severity)
		if left != right {
			return left > right
		}
		return findings[i].ID < findings[j].ID
	})
	limit := 5
	if len(findings) < limit {
		limit = len(findings)
	}
	fmt.Fprintln(writer, "\nTop findings:")
	for index, finding := range findings[:limit] {
		fmt.Fprintf(writer, "  %d. [%s] %s — %s\n", index+1, paint(strings.ToUpper(string(finding.Severity)), finding.Severity, colour), finding.Title, finding.Asset)
	}
}

func writeDetailedSections(writer io.Writer, value model.Report) {
	if len(value.Hosts) > 0 {
		fmt.Fprintln(writer, "\nHosts:")
		limit := min(20, len(value.Hosts))
		for _, host := range value.Hosts[:limit] {
			ports := make([]string, 0, len(host.OpenTCP)+len(host.OpenUDP))
			for _, port := range host.OpenTCP {
				ports = append(ports, fmt.Sprintf("%d/tcp", port))
			}
			for _, port := range host.OpenUDP {
				ports = append(ports, fmt.Sprintf("%d/udp", port))
			}
			fmt.Fprintf(writer, "  %s names=%v reachable=%t ports=%v services=%d\n", host.IP, host.Names, host.Reachable, ports, len(host.Services))
		}
		if len(value.Hosts) > limit {
			fmt.Fprintf(writer, "  … %d more hosts in 03_hosts/host_inventory.json\n", len(value.Hosts)-limit)
		}
	}
	if len(value.Web) > 0 {
		fmt.Fprintln(writer, "\nWeb targets:")
		limit := min(20, len(value.Web))
		for _, result := range value.Web[:limit] {
			fmt.Fprintf(writer, "  %s status=%d title=%q technologies=%v\n", result.FinalURL, result.StatusCode, result.Title, result.Technologies)
		}
		if len(value.Web) > limit {
			fmt.Fprintf(writer, "  … %d more URLs in 06_web/web_results.json\n", len(value.Web)-limit)
		}
	}
	warnings := append([]string(nil), value.Warnings...)
	for _, phase := range value.Phases {
		if phase.Warning != "" {
			warnings = append(warnings, fmt.Sprintf("phase %d (%s): %s", phase.Number, phase.Name, phase.Warning))
		}
	}
	if len(warnings) > 0 {
		fmt.Fprintln(writer, "\nWarnings:")
		limit := min(10, len(warnings))
		for _, warning := range warnings[:limit] {
			fmt.Fprintf(writer, "  - %s\n", warning)
		}
	}
}

func min(left, right int) int {
	if left < right {
		return left
	}
	return right
}

func severityRank(severity model.Severity) int {
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

func paint(value string, severity model.Severity, enabled bool) string {
	if !enabled {
		return value
	}
	code := "36"
	switch severity {
	case model.SeverityCritical:
		code = "31"
	case model.SeverityHigh:
		code = "91"
	case model.SeverityMedium:
		code = "33"
	case model.SeverityLow:
		code = "34"
	}
	return "\x1b[" + code + "m" + value + "\x1b[0m"
}
