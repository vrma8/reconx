package secrets

import (
	"strings"
	"testing"
)

func TestFindAndRedact(t *testing.T) {
	matches := Find("const key = 'AKIA1234567890ABCDEF'; const url='postgres://user:password@db.example.test/app'")
	if len(matches) < 2 { t.Fatalf("matches = %#v", matches) }
	if Redact("abcdefghijkl") == "abcdefghijkl" { t.Fatal("secret was not redacted") }
}

func TestJWTMetadata(t *testing.T) {
	value := "eyJhbGciOiJub25lIn0.eyJpc3MiOiJpc3N1ZXIiLCJzdWIiOiJ1c2VyIiwiZXhwIjoyMDAwMDAwMDAwfQ."
	metadata := JWTMetadata(value)
	if metadata == "" || !strings.Contains(metadata, "iss=issuer") || !strings.Contains(metadata, "sub=user") { t.Fatalf("metadata = %q", metadata) }
}

func TestLooksSensitivePath(t *testing.T) {
	for _, path := range []string{"/.env", "/.git/config", "/backup.sql", "/id_ed25519"} {
		if !LooksSensitivePath(path) { t.Fatalf("expected sensitive path %q", path) }
	}
	if LooksSensitivePath("/assets/app.js") { t.Fatal("ordinary asset marked sensitive") }
}
