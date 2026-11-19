package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/vrma8/reconx/internal/model"
)

func TestTerminalDetailedIncludesCountersAndSections(t *testing.T) {
	buffer := bytes.Buffer{}
	TerminalDetailed(&buffer, model.Report{
		Stats: model.RunStats{Probes: 12, HTTPRequests: 3, DNSQueries: 4, ToolInvocations: 1},
		Hosts: []model.Host{{IP: "192.0.2.1", Reachable: true, OpenTCP: []int{80}}},
		Web:   []model.WebResult{{URL: "http://192.0.2.1", FinalURL: "http://192.0.2.1", StatusCode: 200}},
	}, false, true)
	output := buffer.String()
	for _, marker := range []string{"12 probes", "Hosts:", "Web targets:", "192.0.2.1"} {
		if !strings.Contains(output, marker) {
			t.Fatalf("detailed output missing %q: %q", marker, output)
		}
	}
}

func TestTerminalRanksHighSeverityFindingsFirst(t *testing.T) {
	buffer := bytes.Buffer{}
	Terminal(&buffer, model.Report{
		Findings: []model.Finding{
			{ID: "RX-LOW", Severity: model.SeverityLow, Title: "Low finding"},
			{ID: "RX-HIGH", Severity: model.SeverityHigh, Title: "High finding"},
		},
	}, false)
	output := buffer.String()
	if strings.Index(output, "High finding") > strings.Index(output, "Low finding") {
		t.Fatalf("high severity finding was not ranked first: %q", output)
	}
}

func TestTerminalIncludesSummaryAndFinding(t *testing.T) {
	buffer := bytes.Buffer{}
	Terminal(&buffer, model.Report{Target: model.TargetProfile{Input: "example.test"}, Risk: model.RiskSummary{Score: 3, Level: model.SeverityLow, TotalFindings: 1}, Findings: []model.Finding{{ID: "RX-1", Severity: model.SeverityLow, Title: "Header", Asset: "example.test"}}}, false)
	if output := buffer.String(); !strings.Contains(output, "example.test") || !strings.Contains(output, "Header") {
		t.Fatalf("output = %q", output)
	}
}
