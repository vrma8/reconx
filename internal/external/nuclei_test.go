package external

import (
	"strings"
	"testing"

	"github.com/vrma8/reconx/internal/model"
)

func TestParseNucleiJSONL(t *testing.T) {
	input := `{"template-id":"missing-hsts","matched-at":"https://example.test","host":"example.test","matcher-name":"hsts","extracted-results":["header absent"],"info":{"name":"Missing HSTS","description":"HSTS absent","severity":"medium"}}` + "\n"
	findings, err := ParseNucleiJSONL(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].Severity != model.SeverityMedium || findings[0].Source != "phase7-nuclei" {
		t.Fatalf("findings = %#v", findings)
	}
}

func TestParseNucleiJSONLRejectsInvalid(t *testing.T) {
	if _, err := ParseNucleiJSONL(strings.NewReader("not json\n")); err == nil {
		t.Fatal("expected malformed JSON error")
	}
}
