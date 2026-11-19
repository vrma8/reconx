// Package secrets performs local pattern detection and never validates or uses
// discovered credentials. Values are redacted unless explicitly requested.
package secrets

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/vrma8/reconx/internal/model"
)

type Match struct{ Kind, Value string }

type pattern struct {
	kind        string
	expression  *regexp.Regexp
	severity    model.Severity
	remediation string
}

var patterns = []pattern{
	{"AWS access key ID", regexp.MustCompile(`\b(?:AKIA|ASIA)[A-Z0-9]{16}\b`), model.SeverityHigh, "Revoke and rotate the exposed cloud credential; remove it from the response."},
	{"Google API key", regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`), model.SeverityHigh, "Restrict, rotate, and remove the exposed Google API key."},
	{"private key", regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----`), model.SeverityCritical, "Immediately revoke or replace the private key and remove it from web-accessible content."},
	{"JWT", regexp.MustCompile(`\beyJ[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}\b`), model.SeverityMedium, "Do not expose bearer tokens in public responses; rotate affected tokens."},
	{"database connection string", regexp.MustCompile(`(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^\s"'<>]{8,}`), model.SeverityHigh, "Remove the connection string from public content and rotate the embedded credentials."},
	{"URL-embedded credentials", regexp.MustCompile(`(?i)\bhttps?://[^\s/@:"']{1,128}:[^\s/@"']{1,128}@[^\s/"']+`), model.SeverityHigh, "Remove URL-embedded credentials and rotate the affected account password or token."},
	{"internal IP address", regexp.MustCompile(`\b(?:10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|172\.(?:1[6-9]|2\d|3[0-1])(?:\.\d{1,3}){2})\b`), model.SeverityInfo, "Review whether internal network addressing should be exposed to unauthenticated users."},
	{"internal hostname", regexp.MustCompile(`(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:local|internal|corp|lan)\b`), model.SeverityInfo, "Review whether internal hostnames should be exposed to unauthenticated users."},
	{"generic secret assignment", regexp.MustCompile(`(?i)\b(?:api[_-]?key|secret|password|token)\s*[:=]\s*["']?([A-Za-z0-9_./+=-]{12,})`), model.SeverityHigh, "Remove secrets from client-visible content and rotate the affected value."},
	{"Azure storage account key", regexp.MustCompile(`(?i)\bAccountKey\s*=\s*[A-Za-z0-9+/=]{40,}`), model.SeverityHigh, "Rotate the exposed Azure storage account key and remove it from public content."},
	{"Azure client secret", regexp.MustCompile(`(?i)\b(?:azure_)?client_secret\s*[:=]\s*["']?[A-Za-z0-9._~+/=-]{24,}`), model.SeverityHigh, "Rotate the exposed Azure application client secret and review access logs."},
	{"Bearer token header", regexp.MustCompile(`(?i)\bAuthorization\s*[:=]\s*["']?Bearer\s+[A-Za-z0-9._~-]{20,}`), model.SeverityHigh, "Treat the bearer token as compromised: revoke it and remove it from public content."},
	{"API key header", regexp.MustCompile(`(?i)\b(?:X-Api-Key|X-Auth-Token|X-Access-Token)\s*[:=]\s*["']?[A-Za-z0-9._-]{16,}`), model.SeverityHigh, "Rotate the exposed API token and remove the header value from public content."},
}

func Find(body string) []Match {
	const maximumMatches = 1000
	matches := make([]Match, 0)
	seen := map[string]struct{}{}
	for _, candidate := range patterns {
		for _, value := range candidate.expression.FindAllString(body, -1) {
			if len(matches) >= maximumMatches {
				return matches
			}
			key := candidate.kind + "\x00" + value
			if _, found := seen[key]; found {
				continue
			}
			seen[key] = struct{}{}
			matches = append(matches, Match{Kind: candidate.kind, Value: value})
		}
	}
	return matches
}

func Findings(url string, body string, showSecrets bool) []model.Finding {
	output := make([]model.Finding, 0)
	for _, match := range Find(body) {
		var selected pattern
		for _, candidate := range patterns {
			if candidate.kind == match.Kind {
				selected = candidate
				break
			}
		}
		evidence := Redact(match.Value)
		if metadata := JWTMetadata(match.Value); match.Kind == "JWT" && metadata != "" {
			evidence += " " + metadata
		}
		if showSecrets {
			evidence = match.Value
		}
		output = append(output, model.Finding{
			Severity: selected.severity, Title: "Potential " + match.Kind + " exposed in web content",
			Description: "A credential-like value matched a local detector. Reconx does not attempt to validate or use discovered values.",
			Evidence:    evidence, URL: url, Asset: url, MITRE: []string{"T1552.001"}, Remediation: selected.remediation,
			Confidence: "medium", Source: "phase8-secrets",
		})
	}
	return output
}

// JWTMetadata reads only the public JWT payload fields needed for report
// triage. Signature validation and token use are intentionally out of scope.
func JWTMetadata(value string) string {
	parts := strings.Split(value, ".")
	if len(parts) != 3 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims map[string]any
	if json.Unmarshal(payload, &claims) != nil {
		return ""
	}
	values := make([]string, 0, 3)
	for _, key := range []string{"iss", "sub"} {
		if value, ok := claims[key].(string); ok && value != "" {
			values = append(values, key+"="+value)
		}
	}
	if expiration, ok := claims["exp"]; ok {
		var seconds int64
		switch value := expiration.(type) {
		case float64:
			seconds = int64(value)
		case string:
			seconds, _ = strconv.ParseInt(value, 10, 64)
		}
		if seconds > 0 {
			values = append(values, "exp="+time.Unix(seconds, 0).UTC().Format(time.RFC3339))
		}
	}
	return strings.Join(values, " ")
}

func Redact(value string) string {
	if len(value) <= 8 {
		return "[redacted]"
	}
	digest := sha256.Sum256([]byte(value))
	return fmt.Sprintf("%s…%s [sha256:%x]", value[:4], value[len(value)-4:], digest[:4])
}

func LooksSensitivePath(path string) bool {
	path = strings.ToLower(path)
	for _, suffix := range []string{".env", ".git/config", ".htaccess", "web.config", "config.php", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", ".bak", ".old", ".sql", ".swp", ".pem", ".key"} {
		if strings.Contains(path, suffix) {
			return true
		}
	}
	return false
}
