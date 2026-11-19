package orchestrator

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/vrma8/reconx/internal/config"
	"github.com/vrma8/reconx/internal/httpx"
	"github.com/vrma8/reconx/internal/model"
)

func TestEnhancedWebChecksAreBoundedAndArtifactBacked(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "text/html")
		if request.URL.Path == "/.env" {
			writer.WriteHeader(http.StatusOK)
			return
		}
		_, _ = writer.Write([]byte(`<html><script src="https://cdn.example.invalid/app.js"></script>` + request.URL.Query().Get("q") + `</html>`))
	}))
	defer server.Close()

	root := t.TempDir()
	state := model.NewState(model.TargetProfile{})
	engine := &Engine{
		Config: config.Config{
			Timeout:          time.Second,
			UserAgent:        "reconx-test",
			HeaderScore:      true,
			SRIChecks:        true,
			TLSAssessment:    true,
			ActiveWAF:        true,
			ParameterFuzzing: true,
			SensitiveFiles:   true,
		},
		Workspace: &Workspace{Root: root},
		State:     state,
	}
	web := []model.WebResult{{
		FinalURL:   server.URL + "/",
		Host:       server.Listener.Addr().String(),
		StatusCode: http.StatusOK,
		Headers:    map[string]string{"Content-Type": "text/html"},
		Body:       `<html><script src="https://cdn.example.invalid/app.js"></script><form action="/" method="get"><input name="q"></form></html>`,
		Forms:      []model.WebForm{{Action: "/", Fields: []string{"q"}}},
	}}

	if err := engine.runEnhancedWebChecks(context.Background(), httpx.New(time.Second, "reconx-test"), web, map[string][]string{}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"header_scores.json", "sri_checks.json", "tls_assessments.json", "waf_probes.json", "parameter_probes.json", "sensitive_paths.json"} {
		if _, err := os.ReadFile(filepath.Join(root, "06_web", name)); err != nil {
			t.Fatalf("missing %s: %v", name, err)
		}
	}
	_, _, _, _, findings, _, _ := state.Snapshot()
	seen := map[string]bool{}
	for _, finding := range findings {
		seen[finding.Source] = true
	}
	for _, source := range []string{"phase6-sri", "phase6-sensitive-path", "phase6-parameter-probe"} {
		if !seen[source] {
			t.Fatalf("missing finding source %s in %#v", source, seen)
		}
	}
	if engine.stats.HTTPRequests < 20 || engine.stats.HTTPRequests > 100 {
		t.Fatalf("active web requests are not bounded: %d", engine.stats.HTTPRequests)
	}
}
