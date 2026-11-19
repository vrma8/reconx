package httpx

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestProbeFingerprintsAndExtractsLinks(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Server", "test-server")
		writer.Header().Set("Content-Type", "text/html")
		_, _ = writer.Write([]byte("<html><title> Demo </title><a href='/next'>next</a><script src='https://example.org/app.js'></script>wp-content</html>"))
	}))
	defer server.Close()
	result := New(time.Second, "test").Probe(context.Background(), server.URL)
	if result.Error != "" || result.StatusCode != http.StatusOK {
		t.Fatalf("probe = %#v", result)
	}
	if result.Title != "Demo" {
		t.Fatalf("title = %q", result.Title)
	}
	if len(result.Links) != 2 {
		t.Fatalf("links = %#v", result.Links)
	}
	if !strings.Contains(strings.Join(result.Technologies, ","), "wordpress") {
		t.Fatalf("fingerprint = %#v", result.Technologies)
	}
}

func TestProbeHead(t *testing.T) {
	method := ""
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		method = request.Method
		writer.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()
	result := New(time.Second, "test").ProbeHead(context.Background(), server.URL)
	if result.StatusCode != http.StatusForbidden || method != http.MethodHead {
		t.Fatalf("result=%#v method=%s", result, method)
	}
}

func TestExtractFormsAndAPIEndpoints(t *testing.T) {
	base, _ := http.NewRequest(http.MethodGet, "https://example.com/app", nil)
	body := `<form action="/login" method="post"><input name="user"><input name="password"></form><script>fetch('/api/v1/me'); axios.get('/api/v1/projects')</script>`
	forms := ExtractForms(base.URL, body)
	if len(forms) != 1 || forms[0].Action != "https://example.com/login" || forms[0].Method != "POST" || len(forms[0].Fields) != 2 {
		t.Fatalf("forms = %#v", forms)
	}
	endpoints := ExtractAPIEndpoints(base.URL, body)
	if len(endpoints) != 2 || endpoints[0] != "https://example.com/api/v1/me" {
		t.Fatalf("endpoints = %#v", endpoints)
	}
}

func TestRobotsDisallows(t *testing.T) {
	paths := RobotsDisallows("User-agent: *\nDisallow: /private\nDisallow: /tmp # note\nAllow: /public\n")
	if len(paths) != 2 || !isDisallowed("/private/data", paths) || isDisallowed("/public", paths) {
		t.Fatalf("paths = %#v", paths)
	}
}

func TestExtractLinksFiltersUnsafeSchemes(t *testing.T) {
	base, _ := http.NewRequest(http.MethodGet, "https://example.com/a", nil)
	links := ExtractLinks(base.URL, `<a href="javascript:alert(1)">x</a><a href="/safe">safe</a>`)
	if len(links) != 1 || links[0] != "https://example.com/safe" {
		t.Fatalf("links = %#v", links)
	}
}
