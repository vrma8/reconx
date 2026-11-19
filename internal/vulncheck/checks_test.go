package vulncheck

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRunIsBoundedAndReportsReflection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		_, _ = writer.Write([]byte(request.URL.Query().Get("q")))
	}))
	defer server.Close()
	findings := Run(context.Background(), []Target{{URL: server.URL + "/?q=safe", Params: []string{"q"}}}, time.Second, 6)
	if len(findings) == 0 {
		t.Fatal("expected at least one active-check lead")
	}
	for _, finding := range findings {
		if finding.Source != "phase7-native" || finding.Evidence == "" {
			t.Fatalf("unexpected finding = %#v", finding)
		}
	}
}

func TestRunWithoutParametersIsSafe(t *testing.T) {
	if findings := Run(context.Background(), []Target{{URL: "https://example.test/"}}, time.Second, 3); len(findings) != 0 {
		t.Fatalf("unexpected findings = %#v", findings)
	}
}
