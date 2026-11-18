package cloud

import (
	"strings"
	"testing"
)

func TestCandidatesDeriveProviderValidBoundedPermutations(t *testing.T) {
	values := Candidates([]string{"api.Example.com", "www.example.com", "api.example.com"}, 16)
	if len(values) != 16 { t.Fatalf("candidate count = %d", len(values)) }
	seenProvider := map[string]bool{}
	for _, value := range values {
		seenProvider[value.Provider] = true
		if value.Name == "" || value.URL == "" { t.Fatalf("invalid candidate = %#v", value) }
	}
	for _, provider := range []string{"AWS S3", "Azure Blob", "Google Cloud Storage", "DigitalOcean Spaces"} {
		if !seenProvider[provider] { t.Fatalf("missing provider %q: %#v", provider, values) }
	}
	for _, value := range values {
		if value.Provider == "Google Cloud Storage" && !strings.Contains(value.URL, ".storage.googleapis.com/") {
			t.Fatalf("GCS virtual-host endpoint = %q", value.URL)
		}
	}
}

func TestCandidatesRejectInvalidNames(t *testing.T) {
	if values := Candidates([]string{"a", "bad_name.example"}, 10); len(values) != 0 { t.Fatalf("values = %#v", values) }
}

func TestNeedsGETFallbackOnlyForRejectedHead(t *testing.T) {
	if !NeedsGETFallback(405, "") || !NeedsGETFallback(501, "") { t.Fatal("expected HEAD fallback") }
	if NeedsGETFallback(403, "") || NeedsGETFallback(0, "timeout") { t.Fatal("unexpected GET fallback") }
}

func TestClassifyCloudProbeConservatively(t *testing.T) {
	candidate := Candidate{Provider: "AWS S3", Name: "example-assets", URL: "https://example-assets.s3.amazonaws.com/"}
	if got := Classify(candidate, 200, "").Status; got != "publicly_readable_or_listable" { t.Fatalf("200 status = %q", got) }
	if got := Classify(candidate, 403, "").Status; got != "exists_or_access_restricted" { t.Fatalf("403 status = %q", got) }
	if got := Classify(candidate, 404, "").Status; got != "not_found" { t.Fatalf("404 status = %q", got) }
	if got := Classify(candidate, 0, "timeout").Status; got != "error" { t.Fatalf("error status = %q", got) }
}
