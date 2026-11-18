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
	level := strings.ToUpper(string(value.Risk.Level))
	fmt.Fprintln(writer, "\nRECONX — authorized reconnaissance summary")
	fmt.Fprintf(writer, "Target: %s\nRisk: %s (%d/100)\nFindings: %d\nHosts: %d\n", value.Target.Input, paint(level, value.Risk.Level, colour), value.Risk.Score, value.Risk.TotalFindings, len(value.Hosts))
	if len(value.Phases) > 0 {
		fmt.Fprintln(writer, "\nPhases:")
		for _, phase := range value.Phases { fmt.Fprintf(writer, "  [%02d] %-24s %s (%s)\n", phase.Number, phase.Name, strings.ToUpper(phase.Status), phase.Duration.Round(1e6)) }
	}
	if len(value.Findings) == 0 { return }
	findings := append([]model.Finding(nil), value.Findings...)
	sort.SliceStable(findings, func(i, j int) bool { return findings[i].ID < findings[j].ID })
	limit := 5; if len(findings) < limit { limit = len(findings) }
	fmt.Fprintln(writer, "\nTop findings:")
	for index, finding := range findings[:limit] { fmt.Fprintf(writer, "  %d. [%s] %s — %s\n", index+1, paint(strings.ToUpper(string(finding.Severity)), finding.Severity, colour), finding.Title, finding.Asset) }
}

func paint(value string, severity model.Severity, enabled bool) string {
	if !enabled { return value }
	code := "36"
	switch severity { case model.SeverityCritical: code="31"; case model.SeverityHigh: code="91"; case model.SeverityMedium: code="33"; case model.SeverityLow: code="34" }
	return "\x1b[" + code + "m" + value + "\x1b[0m"
}
