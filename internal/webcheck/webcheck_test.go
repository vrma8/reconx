package webcheck

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHeaderScoreAndMissingHeaders(t *testing.T) {
	assessment := HeaderScore(map[string]string{"Strict-Transport-Security": "max-age=31536000", "X-Frame-Options": "DENY"})
	if assessment.Score != 40 || len(assessment.Missing) == 0 {
		t.Fatalf("assessment = %#v", assessment)
	}
	full := HeaderScore(map[string]string{
		"Strict-Transport-Security": "max-age=1", "Content-Security-Policy": "default-src 'self'",
		"X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff",
		"Referrer-Policy": "no-referrer", "Permissions-Policy": "geolocation=()", "Cross-Origin-Opener-Policy": "same-origin",
	})
	if full.Score != 100 {
		t.Fatalf("full score = %d", full.Score)
	}
}

func TestCheckSRIOnlyFlagsExternalResources(t *testing.T) {
	page := "https://example.test/index.html"
	body := `<script src="https://cdn.example.org/app.js"></script><script src="https://cdn.example.org/secure.js" integrity="sha256-abc"></script><link rel="stylesheet" href="/local.css">`
	results := CheckSRI(page, body)
	if len(results) != 2 || results[0].HasSRI || !results[1].HasSRI {
		t.Fatalf("SRI results = %#v", results)
	}
}

func TestProbeParametersDetectsReflectionAndErrors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		value := request.URL.Query().Get("q")
		if value == "'" {
			_, _ = writer.Write([]byte("You have an error in your SQL syntax"))
			return
		}
		_, _ = writer.Write([]byte(value))
	}))
	defer server.Close()
	results := ProbeParameters(context.Background(), server.Client(), "test", server.URL+"?q=base", []string{"q"})
	if len(results) != 1 || !results[0].Reflected || results[0].ErrorPattern == "" {
		t.Fatalf("parameter results = %#v", results)
	}
}

func TestProbeSensitivePaths(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodHead {
			t.Errorf("unexpected method %s", request.Method)
		}
		if strings.HasSuffix(request.URL.Path, "/.env") {
			writer.WriteHeader(http.StatusOK)
			return
		}
		writer.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()
	results := ProbeSensitivePaths(context.Background(), server.Client(), "test", []string{server.URL + "/index.html"})
	if len(results) != 1 || results[0].Path != "/.env" || !results[0].Interesting {
		t.Fatalf("sensitive paths = %#v", results)
	}
}

func TestWeakCipherAndTLSVersionNames(t *testing.T) {
	if !weakCipher("TLS_RSA_WITH_3DES_EDE_CBC_SHA") || weakCipher("TLS_AES_256_GCM_SHA384") {
		t.Fatal("weak cipher classification failed")
	}
	if tlsVersionName(0x0304) != "TLS 1.3" {
		t.Fatalf("TLS version name = %q", tlsVersionName(0x0304))
	}
}

func TestProbeWAFRecordsTimingLead(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if strings.Contains(request.URL.RawQuery, "reconx_probe") {
			time.Sleep(650 * time.Millisecond)
		}
		writer.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	client := &http.Client{Timeout: 3 * time.Second}
	result := ProbeWAF(context.Background(), client, "test", server.URL+"/")
	if !result.TimingLead || result.MaxTimingDeltaMS < 500 {
		t.Fatalf("WAF timing result = %#v", result)
	}
}

func TestProbeSensitivePathListIsHEADOnly(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodHead {
			t.Errorf("method = %s", request.Method)
		}
		writer.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	results := ProbeSensitivePathList(context.Background(), server.Client(), "test", []string{server.URL + "/"}, []string{"/backup.sql", "/old.zip"})
	if len(results) != 2 || !results[0].Interesting {
		t.Fatalf("path results = %#v", results)
	}
}
