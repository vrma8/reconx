package external

import (
	"strings"
	"testing"
)

func TestParseNiktoJSON(t *testing.T) {
	input := `{"host":"example.test","port":"80","vulnerabilities":[{"id":"500001","url":"https://example.test/admin","method":"GET","msg":"Admin page exposed","severity":"High"}]}`
	findings, err := ParseNiktoJSON(strings.NewReader(input))
	if err != nil || len(findings) != 1 || findings[0].Source != "phase7-nikto" || findings[0].Severity != "high" {
		t.Fatalf("findings=%#v err=%v", findings, err)
	}
}

func TestParseWPScanJSON(t *testing.T) {
	input := `{"target_url":"https://example.test","plugins":{"easy-digital-downloads":{"instances":[{"url":"https://example.test/wp-content/plugins/easy-digital-downloads/"}],"vulnerabilities":[{"title":"SQL Injection","cve":["CVE-2024-1234"]}]}}}`
	findings, err := ParseWPScanJSON(strings.NewReader(input), "https://example.test")
	if err != nil || len(findings) == 0 || findings[0].Source != "phase7-wpscan" {
		t.Fatalf("findings=%#v err=%v", findings, err)
	}
	if !strings.Contains(findings[0].Title, "CVE-2024-1234") {
		t.Fatalf("unexpected title %q", findings[0].Title)
	}
}

func TestParseSQLMapOutput(t *testing.T) {
	input := "Parameter: id (GET)\n    Type: boolean-based blind\n    Title: AND boolean-based blind\n"
	findings, err := ParseSQLMapOutput(strings.NewReader(input), "https://example.test/?id=1")
	if err != nil || len(findings) != 1 || findings[0].Severity != "critical" {
		t.Fatalf("findings=%#v err=%v", findings, err)
	}
}
