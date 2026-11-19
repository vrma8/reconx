package dns

import (
	"context"
	"testing"
)

func TestValidPrefix(t *testing.T) {
	for _, value := range []string{"api", "api-v2", "admin01"} {
		if !validPrefix(value) {
			t.Fatalf("%q should be valid", value)
		}
	}
	for _, value := range []string{"", "-api", "api-", "api.example", "api_1", "space value"} {
		if validPrefix(value) {
			t.Fatalf("%q should be invalid", value)
		}
	}
}

func TestBruteRateLimitedEmptyRootDoesNotResolve(t *testing.T) {
	if values := BruteRateLimited(context.Background(), "", []string{"api"}, 1, 1); values != nil {
		t.Fatalf("values = %#v", values)
	}
}
