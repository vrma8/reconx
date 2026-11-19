package orchestrator

import (
	"context"
	"net/url"
	"sort"
	"strings"

	"github.com/vrma8/reconx/internal/httpx"
	"github.com/vrma8/reconx/internal/model"
	"github.com/vrma8/reconx/internal/webcheck"
)

// Active web checks are deliberately capped: they are optional probes against
// an authorized target, never a general-purpose fuzzer.
const (
	maxWebCheckTargets      = 3
	maxWebCheckParameters   = 3
	maxWebCheckSRIResources = 100
)

// runEnhancedWebChecks adds explainable header/SRI/TLS assessment and opt-in
// bounded active probes. Every generated artifact is JSON so reports and diff
// tooling can consume it without interpreting tool-specific console output.
func (e *Engine) runEnhancedWebChecks(ctx context.Context, client *httpx.Client, web []model.WebResult, parameters map[string][]string) error {
	headerScores := map[string]webcheck.HeaderAssessment{}
	if e.Config.HeaderScore {
		for _, result := range web {
			if result.FinalURL != "" {
				headerScores[result.FinalURL] = webcheck.HeaderScore(result.Headers)
			}
		}
	}

	sriResources := []webcheck.SRIResult{}
	if e.Config.SRIChecks {
		for _, result := range web {
			if len(sriResources) >= maxWebCheckSRIResources {
				break
			}
			if result.FinalURL == "" || !strings.Contains(strings.ToLower(result.Headers["Content-Type"]), "text/html") {
				continue
			}
			remaining := maxWebCheckSRIResources - len(sriResources)
			found := webcheck.CheckSRI(result.FinalURL, result.Body)
			if len(found) > remaining {
				found = found[:remaining]
			}
			sriResources = append(sriResources, found...)
		}
	}

	targets := representativeWebTargets(web, parameters, maxWebCheckTargets)

	tlsAssessments := []webcheck.TLSAssessment{}
	if e.Config.TLSAssessment {
		for _, target := range targets {
			if !strings.HasPrefix(target, "https://") {
				continue
			}
			e.stats.HTTPRequests++
			tlsAssessments = append(tlsAssessments, webcheck.AssessTLS(ctx, target, e.Config.Timeout))
		}
	}

	wafResults := []webcheck.WAFResult{}
	if e.Config.ActiveWAF {
		for _, target := range targets {
			e.stats.HTTPRequests += 4
			wafResults = append(wafResults, webcheck.ProbeWAF(ctx, client.HTTPClient(), e.Config.UserAgent, target))
		}
	}

	parameterResults := []webcheck.ParameterResult{}
	if e.Config.ParameterFuzzing {
		for _, target := range targets {
			names := append([]string(nil), parameters[target]...)
			for _, result := range web {
				if result.FinalURL != target {
					continue
				}
				if parsed, err := url.Parse(target); err == nil {
					for key := range parsed.Query() {
						names = append(names, key)
					}
				}
				for _, form := range result.Forms {
					actionTarget := form.Action
					if action, err := url.Parse(form.Action); err == nil {
						if base, err := url.Parse(target); err == nil {
							actionTarget = base.ResolveReference(action).String()
						}
					}
					if actionTarget != "" && actionTarget != target {
						continue
					}
					names = append(names, form.Fields...)
				}
			}
			names = sortedUnique(names)
			if len(names) > maxWebCheckParameters {
				names = names[:maxWebCheckParameters]
			}
			if len(names) == 0 {
				continue
			}
			e.stats.HTTPRequests += len(names) * 2
			parameterResults = append(parameterResults, webcheck.ProbeParameters(ctx, client.HTTPClient(), e.Config.UserAgent, target, names)...)
		}
	}

	sensitiveResults := []webcheck.SensitivePathResult{}
	if e.Config.SensitiveFiles {
		seeds := targets
		if len(seeds) > 2 {
			seeds = seeds[:2]
		}
		e.stats.HTTPRequests += len(seeds) * 22
		sensitiveResults = webcheck.ProbeSensitivePaths(ctx, client.HTTPClient(), e.Config.UserAgent, seeds)
	}

	if err := e.Workspace.WriteJSON("06_web/header_scores.json", headerScores); err != nil {
		return err
	}
	if err := e.Workspace.WriteJSON("06_web/sri_checks.json", sriResources); err != nil {
		return err
	}
	if err := e.Workspace.WriteJSON("06_web/tls_assessments.json", tlsAssessments); err != nil {
		return err
	}
	if err := e.Workspace.WriteJSON("06_web/waf_probes.json", wafResults); err != nil {
		return err
	}
	if err := e.Workspace.WriteJSON("06_web/parameter_probes.json", parameterResults); err != nil {
		return err
	}
	if err := e.Workspace.WriteJSON("06_web/sensitive_paths.json", sensitiveResults); err != nil {
		return err
	}

	for _, resource := range sriResources {
		if !resource.External || resource.HasSRI {
			continue
		}
		e.State.AddFinding(model.Finding{
			Severity:    model.SeverityLow,
			Title:       "External resource without Subresource Integrity",
			Description: "An externally hosted script or stylesheet is loaded without an integrity attribute.",
			Evidence:    resource.Resource,
			Asset:       assetFromURL(resource.Page),
			URL:         resource.Page,
			MITRE:       []string{"T1189"},
			Remediation: "Pin third-party assets with Subresource Integrity and keep the pinned versions patched.",
			Confidence:  "high",
			Source:      "phase6-sri",
		})
	}
	for _, assessment := range tlsAssessments {
		if assessment.HostnameValid && assessment.ChainValid && !assessment.WeakProtocol && !assessment.WeakCipher {
			continue
		}
		notes := append([]string(nil), assessment.Notes...)
		if !assessment.HostnameValid {
			notes = append(notes, "hostname does not match the certificate")
		}
		if !assessment.ChainValid {
			notes = append(notes, "certificate chain is not trusted")
		}
		if assessment.WeakProtocol {
			notes = append(notes, "weak TLS protocol")
		}
		if assessment.WeakCipher {
			notes = append(notes, "weak TLS cipher")
		}
		e.State.AddFinding(model.Finding{
			Severity:    model.SeverityMedium,
			Title:       "TLS validation issue",
			Description: "A TLS handshake with certificate verification enabled exposed a validation or protocol weakness.",
			Evidence:    strings.Join(notes, "; "),
			Asset:       assetFromURL(assessment.URL),
			URL:         assessment.URL,
			MITRE:       []string{"T1573"},
			Remediation: "Install a valid certificate chain, match the served hostname, and disable obsolete TLS versions and ciphers.",
			Confidence:  "high",
			Source:      "phase6-tls",
		})
	}
	for _, result := range wafResults {
		if !result.Detected {
			continue
		}
		e.State.AddFinding(model.Finding{
			Severity:    model.SeverityInfo,
			Title:       "WAF block signal observed",
			Description: "Bounded harmless payloads produced a block signal; the result is a lead and does not prove a WAF's presence or efficacy.",
			Evidence:    strings.Join(result.Signatures, "; "),
			Asset:       assetFromURL(result.URL),
			URL:         result.URL,
			MITRE:       []string{"T1595"},
			Remediation: "Treat this as context for other findings and validate protection behavior with the application owner.",
			Confidence:  "low",
			Source:      "phase6-waf-probe",
		})
	}
	for _, result := range parameterResults {
		if !result.Reflected && result.ErrorPattern == "" {
			continue
		}
		e.State.AddFinding(model.Finding{
			Severity:    model.SeverityMedium,
			Title:       "Parameter reflection or error pattern",
			Description: "A bounded parameter probe observed reflection or a known error pattern; manual validation is required before treating this as injection.",
			Evidence:    "parameter=" + result.Parameter + "; reflected=" + boolText(result.Reflected) + "; error=" + result.ErrorPattern,
			Asset:       assetFromURL(result.URL),
			URL:         result.URL,
			MITRE:       []string{"T1190"},
			Remediation: "Validate the parameter manually and use parameterized queries, output encoding, and generic error handling where appropriate.",
			Confidence:  "low",
			Source:      "phase6-parameter-probe",
		})
	}
	for _, result := range sensitiveResults {
		if !result.Interesting {
			continue
		}
		e.State.AddFinding(model.Finding{
			Severity:    model.SeverityMedium,
			Title:       "Potentially exposed sensitive path",
			Description: "A HEAD request to a high-signal path returned HTTP 200. Contents were not downloaded or inspected.",
			Evidence:    result.Path + " -> " + itoa(result.StatusCode),
			Asset:       assetFromURL(result.URL),
			URL:         result.URL,
			MITRE:       []string{"T1552"},
			Remediation: "Confirm the path with the application owner and remove or protect unintended public files.",
			Confidence:  "medium",
			Source:      "phase6-sensitive-path",
		})
	}
	return nil
}

func representativeWebTargets(web []model.WebResult, parameters map[string][]string, maximum int) []string {
	byHost := map[string][]string{}
	add := func(host, target string) {
		if host == "" || target == "" {
			return
		}
		for _, existing := range byHost[host] {
			if existing == target {
				return
			}
		}
		byHost[host] = append(byHost[host], target)
	}
	for _, result := range web {
		if result.FinalURL == "" || result.StatusCode == 0 {
			continue
		}
		host := assetFromURL(result.FinalURL)
		if host == "" {
			continue
		}
		add(host, result.FinalURL)
		for _, form := range result.Forms {
			action := form.Action
			if parsedAction, err := url.Parse(form.Action); err == nil {
				if base, err := url.Parse(result.FinalURL); err == nil {
					action = base.ResolveReference(parsedAction).String()
				}
			}
			if assetFromURL(action) == host {
				add(host, action)
			}
		}
	}
	hosts := make([]string, 0, len(byHost))
	for host := range byHost {
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)
	seen := map[string]struct{}{}
	for _, host := range hosts {
		if len(seen) >= maximum {
			break
		}
		candidates := byHost[host]
		sort.Strings(candidates)
		seen[candidates[0]] = struct{}{}
		if len(seen) >= maximum {
			break
		}
		for _, candidate := range candidates[1:] {
			if len(parameters[candidate]) > 0 {
				seen[candidate] = struct{}{}
				break
			}
		}
	}
	output := make([]string, 0, len(seen))
	for target := range seen {
		output = append(output, target)
	}
	sort.Strings(output)
	return output
}

func assetFromURL(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return parsed.Host
}

func boolText(value bool) string {
	if value {
		return "true"
	}
	return "false"
}

func itoa(value int) string {
	if value == 0 {
		return "0"
	}
	negative := value < 0
	if negative {
		value = -value
	}
	buffer := [20]byte{}
	index := len(buffer)
	for value > 0 {
		index--
		buffer[index] = byte('0' + value%10)
		value /= 10
	}
	if negative {
		index--
		buffer[index] = '-'
	}
	return string(buffer[index:])
}
