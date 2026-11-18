// Package httpx contains the HTTP probe, fingerprint and bounded crawler.
package httpx

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/vrma8/reconx/internal/model"
	"github.com/vrma8/reconx/internal/utils"
)

const maxBodyBytes = 1 << 20

var (
	titlePattern       = regexp.MustCompile(`(?is)<title[^>]*>\s*(.*?)\s*</title>`)
	linkPattern        = regexp.MustCompile(`(?is)(?:href|src)\s*=\s*["']([^"'#\s]+)`)
	formPattern        = regexp.MustCompile(`(?is)<form\b([^>]*)>(.*?)</form\s*>`)
	attributePattern   = regexp.MustCompile(`(?is)\b([a-z_-]+)\s*=\s*["']([^"']*)["']`)
	inputNamePattern   = regexp.MustCompile(`(?is)<(?:input|textarea|select)\b[^>]*\bname\s*=\s*["']?([a-z0-9_.\-]+)`)
	apiEndpointPattern = regexp.MustCompile(`(?is)(?:fetch|axios\.(?:get|post|put|delete|patch)|XMLHttpRequest)\s*\(?\s*["']([^"'\s]+)`)
)

type Client struct { client *http.Client; userAgent string }

func New(timeout time.Duration, userAgent string) *Client {
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment, DialContext: (&net.Dialer{Timeout: timeout, KeepAlive: 30*time.Second}).DialContext,
		ForceAttemptHTTP2: true, MaxIdleConns: 100, MaxIdleConnsPerHost: 10, IdleConnTimeout: 30*time.Second,
		TLSHandshakeTimeout: timeout, ResponseHeaderTimeout: timeout, ExpectContinueTimeout: time.Second,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}, // #nosec G402 -- certificate metadata is collected even for invalid certificates.
	}
	return &Client{client: &http.Client{Transport: transport, Timeout: timeout, CheckRedirect: func(request *http.Request, via []*http.Request) error {
		if len(via) >= 5 { return http.ErrUseLastResponse }; return nil
	}}, userAgent: userAgent}
}

func (c *Client) Probe(ctx context.Context, rawURL string) model.WebResult { return c.probe(ctx, rawURL, http.MethodGet) }

// ProbeHead avoids downloading cloud-object bodies when only existence/status
// is needed. Servers that reject HEAD are reported as-is; callers may decide
// whether a bounded GET fallback is appropriate.
func (c *Client) ProbeHead(ctx context.Context, rawURL string) model.WebResult { return c.probe(ctx, rawURL, http.MethodHead) }

func (c *Client) probe(ctx context.Context, rawURL, method string) model.WebResult {
	result := model.WebResult{URL: rawURL, Headers: map[string]string{}}
	parsed, err := url.Parse(rawURL)
	if err != nil { result.Error = err.Error(); return result }
	result.Host = parsed.Hostname()
	request, err := http.NewRequestWithContext(ctx, method, rawURL, nil)
	if err != nil { result.Error = err.Error(); return result }
	request.Header.Set("User-Agent", c.userAgent)
	request.Header.Set("Accept", "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.2")
	response, err := c.client.Do(request)
	if err != nil { result.Error = err.Error(); return result }
	defer response.Body.Close()
	result.StatusCode, result.FinalURL = response.StatusCode, response.Request.URL.String()
	for _, key := range []string{"Server", "X-Powered-By", "Content-Type", "Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy", "Access-Control-Allow-Origin", "Access-Control-Allow-Credentials", "Cross-Origin-Opener-Policy", "Cross-Origin-Resource-Policy"} {
		if value := response.Header.Get(key); value != "" { result.Headers[key] = value }
	}
	content, err := io.ReadAll(io.LimitReader(response.Body, maxBodyBytes))
	if err != nil { result.Error = err.Error(); return result }
	result.Body = string(content)
	result.Title = title(result.Body)
	result.Links = ExtractLinks(response.Request.URL, result.Body)
	result.Forms = ExtractForms(response.Request.URL, result.Body)
	result.APIEndpoints = ExtractAPIEndpoints(response.Request.URL, result.Body)
	result.Cookies = cookieInfo(response.Cookies())
	result.Technologies = Fingerprint(response.Header, result.Body)
	if response.TLS != nil { result.TLS = tlsInfo(response.TLS) }
	return result
}

func (c *Client) Crawl(ctx context.Context, seed string, root string, depth, maximum, workers int, disallowed []string) []model.WebResult {
	if depth < 1 || maximum < 1 { return nil }
	if workers < 1 { workers = 1 }
	type node struct { url string; depth int }
	pending := []node{{url: seed, depth: 0}}
	seen := map[string]struct{}{}
	results := make([]model.WebResult, 0)
	for len(pending) > 0 && len(seen) < maximum {
		batch := pending
		pending = nil
		work := make([]node, 0, len(batch))
		for _, current := range batch {
			if _, found := seen[current.url]; found || len(seen) >= maximum { continue }
			seen[current.url] = struct{}{}
			work = append(work, current)
		}
		if len(work) == 0 { continue }
		jobs := make(chan node)
		out := make(chan model.WebResult, len(work))
		var group sync.WaitGroup
		for i := 0; i < workers; i++ {
			group.Add(1)
			go func() { defer group.Done(); for current := range jobs { select { case <-ctx.Done(): return; default: }; out <- c.Probe(ctx, current.url) } }()
		}
		go func() {
			defer func() { close(jobs); group.Wait(); close(out) }()
			for _, current := range work {
				select { case jobs <- current: case <-ctx.Done(): return }
			}
		}()
		for result := range out {
			results = append(results, result)
			if result.Error != "" { continue }
			for _, link := range result.Links {
				parsed, err := url.Parse(link)
				if err != nil || !utils.IsSubdomainOrEqual(parsed.Hostname(), root) || result.StatusCode >= 400 || isDisallowed(parsed.Path, disallowed) { continue }
				if _, found := seen[link]; !found && batch[0].depth+1 < depth && len(seen)+len(pending) < maximum { pending = append(pending, node{url: link, depth: batch[0].depth + 1}) }
			}
		}
	}
	sort.Slice(results, func(i, j int) bool { return results[i].URL < results[j].URL })
	return results
}

// RobotsDisallows returns simple path-prefix exclusions from a robots.txt
// document. It intentionally applies only explicit Disallow paths and never
// assumes a missing or malformed file grants/denies extra scope.
func RobotsDisallows(body string) []string {
	values := make([]string, 0)
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 || !strings.EqualFold(strings.TrimSpace(parts[0]), "disallow") { continue }
		path := strings.TrimSpace(parts[1])
		if strings.HasPrefix(path, "/") && path != "/" { values = append(values, path) }
	}
	sort.Strings(values)
	return unique(values)
}

func isDisallowed(path string, disallowed []string) bool {
	for _, prefix := range disallowed { if strings.HasPrefix(path, prefix) { return true } }
	return false
}

func ExtractLinks(base *url.URL, body string) []string {
	set := map[string]struct{}{}
	for _, match := range linkPattern.FindAllStringSubmatch(body, -1) {
		if len(match) < 2 { continue }
		candidate, err := base.Parse(strings.TrimSpace(match[1]))
		if err != nil || candidate.Scheme != "http" && candidate.Scheme != "https" { continue }
		candidate.Fragment = ""
		set[candidate.String()] = struct{}{}
	}
	links := make([]string, 0, len(set)); for link := range set { links = append(links, link) }; sort.Strings(links)
	return links
}

func ExtractForms(base *url.URL, body string) []model.WebForm {
	forms := make([]model.WebForm, 0)
	for _, match := range formPattern.FindAllStringSubmatch(body, -1) {
		if len(match) < 3 { continue }
		attributes := htmlAttributes(match[1])
		action := attributes["action"]
		if action != "" { if parsed, err := base.Parse(action); err == nil { action = parsed.String() } } else { action = base.String() }
		method := strings.ToUpper(attributes["method"])
		if method == "" { method = http.MethodGet }
		fields := make([]string, 0)
		for _, field := range inputNamePattern.FindAllStringSubmatch(match[2], -1) { if len(field) > 1 { fields = append(fields, strings.ToLower(field[1])) } }
		forms = append(forms, model.WebForm{Action: action, Method: method, Fields: uniqueSorted(fields)})
	}
	return forms
}

func ExtractAPIEndpoints(base *url.URL, body string) []string {
	values := make([]string, 0)
	for _, match := range apiEndpointPattern.FindAllStringSubmatch(body, -1) {
		if len(match) < 2 { continue }
		candidate, err := base.Parse(strings.TrimSpace(match[1]))
		if err != nil || candidate.Scheme != "http" && candidate.Scheme != "https" { continue }
		candidate.Fragment = ""
		values = append(values, candidate.String())
	}
	return uniqueSorted(values)
}

func htmlAttributes(value string) map[string]string {
	attributes := make(map[string]string)
	for _, match := range attributePattern.FindAllStringSubmatch(value, -1) { if len(match) > 2 { attributes[strings.ToLower(match[1])] = strings.TrimSpace(match[2]) } }
	return attributes
}

func cookieInfo(cookies []*http.Cookie) []model.CookieInfo {
	values := make([]model.CookieInfo, 0, len(cookies))
	for _, cookie := range cookies { values = append(values, model.CookieInfo{Name: cookie.Name, Secure: cookie.Secure, HTTPOnly: cookie.HttpOnly, SameSite: sameSite(cookie.SameSite)}) }
	sort.Slice(values, func(i, j int) bool { return values[i].Name < values[j].Name })
	return values
}

func sameSite(value http.SameSite) string {
	switch value { case http.SameSiteStrictMode: return "Strict"; case http.SameSiteLaxMode: return "Lax"; case http.SameSiteNoneMode: return "None"; default: return "" }
}

func Fingerprint(headers http.Header, body string) []string {
	values := make([]string, 0)
	server := headers.Get("Server")
	powered := headers.Get("X-Powered-By")
	if server != "" { values = append(values, "server:"+server) }
	if powered != "" { values = append(values, "powered-by:"+powered) }
	lower := strings.ToLower(body)
	for marker, technology := range map[string]string{"wp-content/":"wordpress", "__next":"next.js", "laravel_session":"laravel", "django":"django", "react":"react", "vue":"vue.js", "drupal-settings-json":"drupal", "shopify":"shopify"} {
		if strings.Contains(lower, marker) { values = append(values, technology) }
	}
	sort.Strings(values)
	return unique(values)
}

func title(body string) string { match := titlePattern.FindStringSubmatch(body); if len(match) < 2 { return "" }; value := strings.Join(strings.Fields(match[1]), " "); if len(value) > 200 { return value[:200] }; return value }
func tlsInfo(state *tls.ConnectionState) *model.TLSInfo {
	info := &model.TLSInfo{Version: tlsVersion(state.Version), Cipher: tls.CipherSuiteName(state.CipherSuite)}
	if len(state.PeerCertificates) == 0 { return info }
	certificate := state.PeerCertificates[0]
	info.Subject, info.Issuer, info.DNSNames, info.NotAfter = certificate.Subject.String(), certificate.Issuer.String(), append([]string(nil), certificate.DNSNames...), certificate.NotAfter.UTC().Format(time.RFC3339)
	info.SelfSigned = certificate.Subject.String() == certificate.Issuer.String()
	return info
}
func tlsVersion(version uint16) string { switch version { case tls.VersionTLS13: return "TLS 1.3"; case tls.VersionTLS12: return "TLS 1.2"; case tls.VersionTLS11: return "TLS 1.1"; case tls.VersionTLS10: return "TLS 1.0"; default: return fmt.Sprintf("0x%x", version) } }
func unique(values []string) []string { seen:=map[string]struct{}{}; result:=make([]string,0,len(values)); for _, value:=range values { if _,found:=seen[value]; !found { seen[value]=struct{}{}; result=append(result,value) } }; return result }
func uniqueSorted(values []string) []string { output := unique(values); sort.Strings(output); return output }
