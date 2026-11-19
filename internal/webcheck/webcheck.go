// Package webcheck implements bounded, correlation-friendly web checks that
// complement the passive crawler. Active probes are opt-in and never modify
// remote state.
package webcheck

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

const timingLeadThreshold = 500 * time.Millisecond

type HeaderAssessment struct {
	Score   int      `json:"score"`
	Missing []string `json:"missing,omitempty"`
}

var headerChecks = []struct {
	Header string
	Weight int
}{
	{"Strict-Transport-Security", 25},
	{"Content-Security-Policy", 25},
	{"X-Frame-Options", 15},
	{"X-Content-Type-Options", 15},
	{"Referrer-Policy", 10},
	{"Permissions-Policy", 5},
	{"Cross-Origin-Opener-Policy", 5},
}

// HeaderScore grades the security headers observed on one response. The
// result is explainable: every missing header is retained with its weight.
func HeaderScore(headers map[string]string) HeaderAssessment {
	score := 0
	missing := make([]string, 0)
	for _, check := range headerChecks {
		if strings.TrimSpace(headers[check.Header]) != "" {
			score += check.Weight
			continue
		}
		if check.Header == "X-Frame-Options" && strings.Contains(strings.ToLower(headers["Content-Security-Policy"]), "frame-ancestors") {
			score += check.Weight
			continue
		}
		missing = append(missing, fmt.Sprintf("%s (-%d)", check.Header, check.Weight))
	}
	if score > 100 {
		score = 100
	}
	return HeaderAssessment{Score: score, Missing: missing}
}

type SRIResult struct {
	Page     string `json:"page"`
	Resource string `json:"resource"`
	External bool   `json:"external"`
	HasSRI   bool   `json:"has_sri"`
}

var (
	scriptTagPattern = regexp.MustCompile(`(?is)<script\b([^>]*)>`)
	linkTagPattern   = regexp.MustCompile(`(?is)<link\b([^>]*)>`)
	attributePattern = regexp.MustCompile(`(?is)\b(src|href)\s*=\s*["']([^"']+)["']`)
)

// CheckSRI reports external scripts and stylesheets that lack an integrity
// attribute. Only syntactically complete tags are considered.
func CheckSRI(page string, body string) []SRIResult {
	base, err := url.Parse(page)
	if err != nil {
		return nil
	}
	output := make([]SRIResult, 0)
	collect := func(pattern *regexp.Regexp) {
		for _, tag := range pattern.FindAllStringSubmatch(body, -1) {
			if len(tag) < 2 {
				continue
			}
			attributes := attributePattern.FindAllStringSubmatch(tag[1], -1)
			for _, attribute := range attributes {
				if len(attribute) < 3 {
					continue
				}
				reference, err := base.Parse(strings.TrimSpace(attribute[2]))
				if err != nil || (reference.Scheme != "http" && reference.Scheme != "https") {
					continue
				}
				external := reference.Hostname() != base.Hostname()
				if !external {
					continue
				}
				output = append(output, SRIResult{Page: page, Resource: reference.String(), External: true, HasSRI: strings.Contains(strings.ToLower(tag[1]), "integrity=")})
			}
		}
	}
	collect(scriptTagPattern)
	collect(linkTagPattern)
	sort.Slice(output, func(i, j int) bool { return output[i].Resource < output[j].Resource })
	return dedupeSRI(output)
}

func dedupeSRI(values []SRIResult) []SRIResult {
	seen := map[string]struct{}{}
	output := make([]SRIResult, 0, len(values))
	for _, value := range values {
		key := value.Page + "\x00" + value.Resource
		if _, found := seen[key]; found {
			continue
		}
		seen[key] = struct{}{}
		output = append(output, value)
	}
	return output
}

type TLSAssessment struct {
	URL           string   `json:"url"`
	Version       string   `json:"version,omitempty"`
	Cipher        string   `json:"cipher,omitempty"`
	HostnameValid bool     `json:"hostname_valid"`
	ChainValid    bool     `json:"chain_valid"`
	Issuer        string   `json:"issuer,omitempty"`
	NotAfter      string   `json:"not_after,omitempty"`
	WeakProtocol  bool     `json:"weak_protocol"`
	WeakCipher    bool     `json:"weak_cipher"`
	Notes         []string `json:"notes,omitempty"`
}

// AssessTLS performs one additional TLS handshake with normal certificate
// verification enabled. The crawler intentionally accepts invalid
// certificates so evidence can still be collected; this pass validates them.
func AssessTLS(ctx context.Context, rawURL string, timeout time.Duration) TLSAssessment {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme != "https" {
		return TLSAssessment{URL: rawURL}
	}
	host := parsed.Hostname()
	port := parsed.Port()
	if port == "" {
		port = "443"
	}
	result := TLSAssessment{URL: rawURL}
	dialer := &net.Dialer{Timeout: timeout}
	connection, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		result.Notes = append(result.Notes, "TLS handshake failed: "+short(err.Error()))
		return result
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(timeout))
	secure := tls.Client(connection, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
	if err := secure.HandshakeContext(ctx); err != nil {
		result.Notes = append(result.Notes, "verified handshake failed: "+short(err.Error()))
		// Retry without verification to record the offered certificate/version.
		insecure := tls.Client(connection, &tls.Config{ServerName: host, InsecureSkipVerify: true}) // #nosec G402 -- evidence collection only.
		if err := insecure.HandshakeContext(ctx); err != nil {
			return result
		}
		secure = insecure
	}
	state := secure.ConnectionState()
	result.Version = tlsVersionName(state.Version)
	result.Cipher = tls.CipherSuiteName(state.CipherSuite)
	result.WeakProtocol = state.Version < tls.VersionTLS12
	result.WeakCipher = weakCipher(result.Cipher)
	if len(state.PeerCertificates) == 0 {
		result.Notes = append(result.Notes, "no leaf certificate presented")
		return result
	}
	leaf := state.PeerCertificates[0]
	result.Issuer = leaf.Issuer.String()
	result.NotAfter = leaf.NotAfter.UTC().Format(time.RFC3339)
	result.HostnameValid = leaf.VerifyHostname(host) == nil
	options := x509.VerifyOptions{DNSName: host, Roots: nil, Intermediates: x509.NewCertPool()}
	for _, certificate := range state.PeerCertificates[1:] {
		options.Intermediates.AddCert(certificate)
	}
	_, err = leaf.Verify(options)
	result.ChainValid = err == nil
	if !result.ChainValid {
		result.Notes = append(result.Notes, "chain validation: "+short(err.Error()))
	}
	return result
}

func weakCipher(name string) bool {
	lower := strings.ToLower(name)
	for _, marker := range []string{"rc4", "3des", "des", "export", "null", "anon"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS10:
		return "TLS 1.0"
	default:
		return fmt.Sprintf("0x%x", version)
	}
}

func short(value string) string {
	if len(value) > 160 {
		return value[:160]
	}
	return value
}

type WAFResult struct {
	URL              string   `json:"url"`
	Detected         bool     `json:"detected"`
	Signatures       []string `json:"signatures,omitempty"`
	Statuses         []int    `json:"statuses,omitempty"`
	TimingLead       bool     `json:"timing_lead,omitempty"`
	MaxTimingDeltaMS int64    `json:"max_timing_delta_ms,omitempty"`
}

var wafPayloads = []string{
	"<script>alert(1)</script>",
	"' OR 1=1--",
	"../../etc/passwd",
}

// ProbeWAF sends a small number of harmless query payloads and compares the
// response with a baseline. It only reports a signal when a block pattern or a
// material status change appears; it is never treated as proof of a WAF.
func ProbeWAF(ctx context.Context, client *http.Client, userAgent string, target string) WAFResult {
	result := WAFResult{URL: target}
	baseline := fetchTimed(ctx, client, userAgent, target)
	baselineStatus, baselineBody := baseline.Status, baseline.Body
	for _, payload := range wafPayloads {
		parsed, err := url.Parse(target)
		if err != nil {
			return result
		}
		query := parsed.Query()
		query.Set("reconx_probe", payload)
		parsed.RawQuery = query.Encode()
		probe := fetchTimed(ctx, client, userAgent, parsed.String())
		status, body := probe.Status, probe.Body
		result.Statuses = append(result.Statuses, status)
		delta := probe.Duration.Milliseconds() - baseline.Duration.Milliseconds()
		if delta > result.MaxTimingDeltaMS {
			result.MaxTimingDeltaMS = delta
		}
		if delta >= timingLeadThreshold.Milliseconds() && baselineStatus > 0 && status == baselineStatus {
			result.TimingLead = true
			result.Signatures = appendUnique(result.Signatures, "timing delay on bounded payload")
		}
		lower := strings.ToLower(body)
		for _, marker := range []string{"blocked by", "request blocked", "access denied", "waf", "mod_security", "forbidden"} {
			if strings.Contains(lower, marker) {
				result.Detected = true
				result.Signatures = appendUnique(result.Signatures, marker)
			}
		}
		if baselineStatus > 0 && status != baselineStatus && (status == 403 || status == 406 || status == 429) && baselineStatus < 400 {
			result.Detected = true
			result.Signatures = appendUnique(result.Signatures, fmt.Sprintf("status %d -> %d", baselineStatus, status))
		}
		if baselineBody != "" && body == "" && status >= 400 {
			result.Detected = true
			result.Signatures = appendUnique(result.Signatures, "empty blocked response body")
		}
	}
	sort.Ints(result.Statuses)
	return result
}

type timedResponse struct {
	Status   int
	Body     string
	Duration time.Duration
}

func fetch(ctx context.Context, client *http.Client, userAgent, target string) (int, string) {
	response := fetchTimed(ctx, client, userAgent, target)
	return response.Status, response.Body
}

func fetchTimed(ctx context.Context, client *http.Client, userAgent, target string) timedResponse {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return timedResponse{}
	}
	request.Header.Set("User-Agent", userAgent)
	start := time.Now()
	response, err := client.Do(request)
	if err != nil {
		return timedResponse{Duration: time.Since(start)}
	}
	defer response.Body.Close()
	content, _ := io.ReadAll(io.LimitReader(response.Body, 64*1024))
	return timedResponse{Status: response.StatusCode, Body: string(content), Duration: time.Since(start)}
}

func appendUnique(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

type ParameterResult struct {
	URL          string `json:"url"`
	Parameter    string `json:"parameter"`
	Reflected    bool   `json:"reflected,omitempty"`
	ErrorPattern string `json:"error_pattern,omitempty"`
	TimeDeltaMS  int64  `json:"time_delta_ms,omitempty"`
}

var errorPatterns = []string{"sql syntax", "mysql_fetch", "pg_query", "uncaught exception", "stack trace", "ora-0"}

// ProbeParameters tests one marker per discovered parameter. Checks are
// reflection/error based; timing uses a short bounded delay and is reported
// as a lead, not as a confirmed injection.
func ProbeParameters(ctx context.Context, client *http.Client, userAgent, target string, parameters []string) []ParameterResult {
	results := make([]ParameterResult, 0, len(parameters))
	marker := "reconxreflectionmarker"
	for _, parameter := range parameters {
		if parameter == "" || len(results) >= 20 {
			continue
		}
		parsed, err := url.Parse(target)
		if err != nil {
			continue
		}
		query := parsed.Query()
		query.Set(parameter, marker)
		parsed.RawQuery = query.Encode()
		baseline := fetchTimed(ctx, client, userAgent, parsed.String())
		entry := ParameterResult{URL: target, Parameter: parameter, Reflected: strings.Contains(baseline.Body, marker)}
		query.Set(parameter, "'")
		parsed.RawQuery = query.Encode()
		errorProbe := fetchTimed(ctx, client, userAgent, parsed.String())
		if delta := errorProbe.Duration.Milliseconds() - baseline.Duration.Milliseconds(); delta >= timingLeadThreshold.Milliseconds() {
			entry.TimeDeltaMS = delta
		}
		for _, pattern := range errorPatterns {
			if strings.Contains(strings.ToLower(errorProbe.Body), pattern) {
				entry.ErrorPattern = pattern
				break
			}
		}
		if entry.Reflected || entry.ErrorPattern != "" {
			results = append(results, entry)
		}
	}
	return results
}

type SensitivePathResult struct {
	URL         string `json:"url"`
	Path        string `json:"path"`
	StatusCode  int    `json:"status_code"`
	Interesting bool   `json:"interesting"`
}

var sensitivePaths = []string{
	"/.env", "/.git/config", "/.git/HEAD", "/.htaccess", "/web.config", "/config.php",
	"/id_rsa", "/id_dsa", "/id_ecdsa", "/id_ed25519", "/backup.sql", "/dump.sql",
	"/db.sql", "/site.zip", "/source.zip", "/app.old", "/index.php.bak", "/.DS_Store",
	"/server-status", "/phpinfo.php", "/swagger.json", "/openapi.json", "/ACTUATOR/env",
}

// FixedSensitivePaths returns the built-in high-signal path list so callers
// can combine it with an operator-supplied wordlist under one hard cap.
func FixedSensitivePaths() []string {
	return append([]string(nil), sensitivePaths...)
}

// ProbeSensitivePaths checks a small, fixed set of high-signal paths. It only
// performs HEAD requests and never downloads file contents.
func ProbeSensitivePaths(ctx context.Context, client *http.Client, userAgent string, seeds []string) []SensitivePathResult {
	output := make([]SensitivePathResult, 0)
	for _, seed := range seeds {
		parsed, err := url.Parse(seed)
		if err != nil {
			continue
		}
		base := *parsed
		base.Path, base.RawQuery, base.Fragment = "", "", ""
		if base.Scheme != "http" && base.Scheme != "https" {
			continue
		}
		for _, path := range sensitivePaths {
			candidate := base
			candidate.Path = path
			request, err := http.NewRequestWithContext(ctx, http.MethodHead, candidate.String(), nil)
			if err != nil {
				continue
			}
			request.Header.Set("User-Agent", userAgent)
			response, err := client.Do(request)
			if err != nil {
				continue
			}
			status := response.StatusCode
			_ = response.Body.Close()
			if status == 200 || status == 301 || status == 302 || status == 403 {
				output = append(output, SensitivePathResult{URL: candidate.String(), Path: path, StatusCode: status, Interesting: status == 200})
			}
		}
	}
	sort.Slice(output, func(i, j int) bool {
		if output[i].URL == output[j].URL {
			return output[i].Path < output[j].Path
		}
		return output[i].URL < output[j].URL
	})
	return output
}

// ProbeSensitivePathList checks a caller-supplied, already-capped path list.
// Only HEAD requests are issued and no response bodies are read.
func ProbeSensitivePathList(ctx context.Context, client *http.Client, userAgent string, seeds []string, paths []string) []SensitivePathResult {
	if len(paths) == 0 {
		return nil
	}
	capped := append([]string(nil), paths...)
	if len(capped) > 500 {
		capped = capped[:500]
	}
	output := make([]SensitivePathResult, 0, len(capped))
	for _, seed := range seeds {
		parsed, err := url.Parse(seed)
		if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
			continue
		}
		base := *parsed
		base.Path, base.RawQuery, base.Fragment = "", "", ""
		for _, path := range capped {
			if !strings.HasPrefix(path, "/") {
				path = "/" + path
			}
			candidate := base
			candidate.Path = path
			request, err := http.NewRequestWithContext(ctx, http.MethodHead, candidate.String(), nil)
			if err != nil {
				continue
			}
			request.Header.Set("User-Agent", userAgent)
			response, err := client.Do(request)
			if err != nil {
				continue
			}
			status := response.StatusCode
			_ = response.Body.Close()
			if status == 200 || status == 301 || status == 302 || status == 403 {
				output = append(output, SensitivePathResult{URL: candidate.String(), Path: path, StatusCode: status, Interesting: status == 200})
			}
		}
	}
	sort.Slice(output, func(i, j int) bool {
		if output[i].URL == output[j].URL {
			return output[i].Path < output[j].Path
		}
		return output[i].URL < output[j].URL
	})
	return output
}
