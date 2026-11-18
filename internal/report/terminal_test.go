package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/vrma8/reconx/internal/model"
)

func TestTerminalIncludesSummaryAndFinding(t *testing.T) {
	buffer := bytes.Buffer{}
	Terminal(&buffer, model.Report{Target:model.TargetProfile{Input:"example.test"}, Risk:model.RiskSummary{Score:3, Level:model.SeverityLow, TotalFindings:1}, Findings:[]model.Finding{{ID:"RX-1", Severity:model.SeverityLow, Title:"Header", Asset:"example.test"}}}, false)
	if output:=buffer.String(); !strings.Contains(output,"example.test") || !strings.Contains(output,"Header") { t.Fatalf("output = %q",output) }
}
