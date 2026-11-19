// Package vulncheck contains bounded, opt-in active checks for common web
// weaknesses. Checks are read-only probes against the authorized target and
// report leads with explicit confidence, never confirmed exploitation.
package vulncheck

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/vrma8/reconx/internal/model"
)

type Target struct {
	URL    string
	Params []string
	Login  bool
}

func newClient(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// Run executes all native checks under a hard request budget.
func Run(ctx context.Context, targets []Target, timeout time.Duration, budget int) []model.Finding {
	if budget < 1 {
		return nil
	}
	client := newClient(timeout)
	findings := make([]model.Finding, 0)
	remaining := budget
	add := func(finding model.Finding) {
		findings = append(findings, finding)
	}
	for _, target := range targets {
		if remaining <= 0 {
			break
		}
		for _, parameter := range target.Params {
			if remaining <= 0 {
				break
			}
			if finding, used := traversal(ctx, client, target.URL, parameter); used {
				remaining--
				if finding != nil {
					add(*finding)
				}
			}
			if remaining <= 0 {
				break
			}
			if finding, used := reflectedXSS(ctx, client, target.URL, parameter); used {
				remaining--
				if finding != nil {
					add(*finding)
				}
			}
			if remaining <= 0 {
				break
			}
			if finding, used := ssrf(ctx, client, target.URL, parameter); used {
				remaining--
				if finding != nil {
					add(*finding)
				}
			}
			if remaining <= 0 {
				break
			}
			if finding, used := idor(ctx, client, target.URL, parameter); used {
				remaining--
				if finding != nil {
					add(*finding)
				}
			}
		}
		if remaining <= 0 {
			break
		}
		if finding, used := authBypass(ctx, client, target.URL); used {
			remaining--
			if finding != nil {
				add(*finding)
			}
		}
		if target.Login {
			for _, credential := range []string{"admin:admin", "root:root", "admin:password"} {
				if remaining <= 0 {
					break
				}
				remaining--
				if finding := defaultCredentials(ctx, client, target.URL, credential); finding != nil {
					add(*finding)
					break
				}
			}
		}
	}
	return dedupe(findings)
}

func request(ctx context.Context, client *http.Client, method, target string, headers map[string]string, form url.Values) (int, string) {
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	request, err := http.NewRequestWithContext(ctx, method, target, body)
	if err != nil {
		return 0, ""
	}
	request.Header.Set("User-Agent", "reconx/1.0 (authorized-active-checks)")
	if form != nil {
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for key, value := range headers {
		request.Header.Set(key, value)
	}
	response, err := client.Do(request)
	if err != nil {
		return 0, ""
	}
	defer response.Body.Close()
	content, _ := io.ReadAll(io.LimitReader(response.Body, 64*1024))
	return response.StatusCode, string(content)
}

func withParam(target, parameter, value string) string {
	parsed, err := url.Parse(target)
	if err != nil {
		return target
	}
	query := parsed.Query()
	query.Set(parameter, value)
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

func finding(severity model.Severity, title, description, url, evidence, mitre, impact, exploitability string) model.Finding {
	return model.Finding{
		Severity: severity, Title: title, Description: description, URL: url, Asset: hostOf(url),
		Evidence: evidence, MITRE: []string{mitre}, Remediation: "Validate the result manually, then apply input validation, access control, or secure configuration as appropriate.",
		Confidence: "low", Source: "phase7-native", Exploitability: exploitability, BusinessImpact: impact,
	}
}

func hostOf(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	return parsed.Hostname()
}

func traversal(ctx context.Context, client *http.Client, target, parameter string) (*model.Finding, bool) {
	if !hasParam(target, parameter) {
		return nil, false
	}
	payload := "../../../../../../etc/passwd"
	status, body := request(ctx, client, http.MethodGet, withParam(target, parameter, payload), nil, nil)
	if status == 0 {
		return nil, true
	}
	if strings.Contains(body, "root:x:0:0:") {
		result := finding(model.SeverityHigh, "Possible path traversal", "A traversal payload returned operating-system file content.", target, "HTTP "+strconv.Itoa(status)+"; unix passwd marker", "T1087", "high", "high")
		return &result, true
	}
	return nil, true
}

func reflectedXSS(ctx context.Context, client *http.Client, target, parameter string) (*model.Finding, bool) {
	if !hasParam(target, parameter) {
		return nil, false
	}
	marker := "<reconx-xss-" + strconv.FormatInt(time.Now().UnixNano(), 36) + ">"
	_, body := request(ctx, client, http.MethodGet, withParam(target, parameter, marker), nil, nil)
	if strings.Contains(body, marker) {
		result := finding(model.SeverityMedium, "Possible reflected XSS", "A unique marker supplied in a query parameter was reflected verbatim in the response.", target, "marker reflected in response body", "T1059.007", "medium", "medium")
		result.Confidence = "medium"
		return &result, true
	}
	return nil, true
}

func ssrf(ctx context.Context, client *http.Client, target, parameter string) (*model.Finding, bool) {
	if !hasParam(target, parameter) {
		return nil, false
	}
	payload := "http://169.254.169.254/latest/meta-data/"
	status, body := request(ctx, client, http.MethodGet, withParam(target, parameter, payload), nil, nil)
	if status == 0 {
		return nil, true
	}
	lower := strings.ToLower(body)
	for _, marker := range []string{"ami-id", "instance-id", "metadata", "169.254.169.254"} {
		if strings.Contains(lower, marker) {
			result := finding(model.SeverityHigh, "Possible SSRF", "A metadata-service URL supplied in a parameter influenced the server response.", target, "HTTP "+strconv.Itoa(status)+"; marker: "+marker, "T1190", "high", "medium")
			return &result, true
		}
	}
	return nil, true
}

var numericValue = regexp.MustCompile(`^\d+$`)

func idor(ctx context.Context, client *http.Client, target, parameter string) (*model.Finding, bool) {
	parsed, err := url.Parse(target)
	if err != nil {
		return nil, false
	}
	original := parsed.Query().Get(parameter)
	if !numericValue.MatchString(original) {
		return nil, false
	}
	number, err := strconv.Atoi(original)
	if err != nil || number > 1_000_000 {
		return nil, false
	}
	baselineStatus, baselineBody := request(ctx, client, http.MethodGet, target, nil, nil)
	next := withParam(target, parameter, strconv.Itoa(number+1))
	status, body := request(ctx, client, http.MethodGet, next, nil, nil)
	if status == http.StatusOK && baselineStatus == http.StatusOK && body != "" && body != baselineBody {
		result := finding(model.SeverityMedium, "Possible insecure direct object reference", "A sequential identifier returned a different, apparently valid resource.", next, "HTTP 200 for adjacent identifier", "T1078", "medium", "medium")
		return &result, true
	}
	return nil, true
}

func authBypass(ctx context.Context, client *http.Client, target string) (*model.Finding, bool) {
	baselineStatus, baselineBody := request(ctx, client, http.MethodGet, target, nil, nil)
	if baselineStatus == 0 || baselineStatus < 400 {
		return nil, false
	}
	for _, headers := range []map[string]string{
		{"X-Original-URL": "/admin"},
		{"X-Rewrite-URL": "/admin"},
		{"X-Forwarded-For": "127.0.0.1"},
	} {
		status, body := request(ctx, client, http.MethodGet, target, headers, nil)
		if status == http.StatusOK && body != baselineBody {
			keys := make([]string, 0, len(headers))
			for key := range headers {
				keys = append(keys, key)
			}
			result := finding(model.SeverityHigh, "Possible authentication bypass", "A proxy/rewrite header produced a successful response where the baseline was denied.", target, fmt.Sprintf("%s produced HTTP 200", strings.Join(keys, ",")), "T1098", "high", "high")
			return &result, true
		}
	}
	return nil, true
}

func defaultCredentials(ctx context.Context, client *http.Client, target, credential string) *model.Finding {
	parts := strings.SplitN(credential, ":", 2)
	form := url.Values{"username": {parts[0]}, "password": {parts[1]}}
	status, body := request(ctx, client, http.MethodPost, target, nil, form)
	if status >= 200 && status < 400 {
		lower := strings.ToLower(body)
		for _, marker := range []string{"logout", "dashboard", "welcome", "signed in"} {
			if strings.Contains(lower, marker) {
				result := finding(model.SeverityCritical, "Possible default credentials accepted", "A common default credential pair produced an authenticated-looking response.", target, "HTTP "+strconv.Itoa(status)+"; marker: "+marker, "T1110.001", "high", "high")
				result.Confidence = "low"
				return &result
			}
		}
	}
	return nil
}

func hasParam(target, parameter string) bool {
	parsed, err := url.Parse(target)
	if err != nil {
		return false
	}
	_, found := parsed.Query()[parameter]
	return found
}

func dedupe(values []model.Finding) []model.Finding {
	seen := map[string]struct{}{}
	output := make([]model.Finding, 0, len(values))
	for _, value := range values {
		key := value.Title + "\x00" + value.URL + "\x00" + value.Evidence
		if _, found := seen[key]; found {
			continue
		}
		seen[key] = struct{}{}
		output = append(output, value)
	}
	return output
}
