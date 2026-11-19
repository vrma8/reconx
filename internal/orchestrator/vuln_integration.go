package orchestrator

import (
	"context"
	"net/url"
	"os"
	"sort"
	"strings"

	"github.com/vrma8/reconx/internal/external"
	"github.com/vrma8/reconx/internal/model"
	"github.com/vrma8/reconx/internal/vulncheck"
)

const (
	maxNativeCheckTargets = 3
	maxNativeCheckParams  = 3
	nativeCheckBudget     = 60
)

// parseToolReportFile normalizes supported tool reports into findings. Raw
// output remains on disk; a parse failure never discards the raw artifact.
func (e *Engine) parseToolReportFile(tool, path, target string) {
	content, err := os.Open(e.Workspace.Path(strings.Split(path, "/")...))
	if err != nil {
		e.State.AddWarning("read " + tool + " report: " + err.Error())
		return
	}
	defer content.Close()
	var findings []model.Finding
	switch tool {
	case "nikto":
		findings, err = external.ParseNiktoJSON(content)
	case "wpscan":
		findings, err = external.ParseWPScanJSON(content, target)
	case "sqlmap":
		findings, err = external.ParseSQLMapOutput(content, target)
	default:
		return
	}
	if err != nil {
		e.State.AddWarning("parse " + tool + " report: " + err.Error())
		return
	}
	for _, finding := range findings {
		e.State.AddFinding(finding)
	}
}

// runNativeVulnChecks converts the discovered parameter inventory into a small
// target set. Default profiles do not enable it; the hard budget is independent
// of report size.
func (e *Engine) runNativeVulnChecks(ctx context.Context, web []model.WebResult) {
	parametersByURL := map[string][]string{}
	for _, result := range web {
		if result.StatusCode == 0 || result.FinalURL == "" {
			continue
		}
		names := make([]string, 0)
		if parsed, err := url.Parse(result.FinalURL); err == nil {
			for key := range parsed.Query() {
				names = append(names, key)
			}
		}
		for _, form := range result.Forms {
			for _, field := range form.Fields {
				if form.Action != "" && form.Action != result.FinalURL {
					continue
				}
				names = append(names, field)
			}
		}
		sort.Strings(names)
		parametersByURL[result.FinalURL] = sortedUnique(names)
	}
	targets := make([]string, 0, len(parametersByURL))
	for target := range parametersByURL {
		targets = append(targets, target)
	}
	sort.Strings(targets)
	checks := make([]vulncheck.Target, 0, maxNativeCheckTargets)
	for _, target := range targets {
		if len(checks) >= maxNativeCheckTargets {
			break
		}
		names := parametersByURL[target]
		if len(names) > maxNativeCheckParams {
			names = names[:maxNativeCheckParams]
		}
		lower := strings.ToLower(target)
		checks = append(checks, vulncheck.Target{URL: target, Params: names, Login: strings.Contains(lower, "login") || strings.Contains(lower, "signin") || strings.Contains(lower, "admin")})
	}
	findings := vulncheck.Run(ctx, checks, e.Config.Timeout, nativeCheckBudget)
	e.stats.HTTPRequests += countAvailableChecks(checks)
	for _, finding := range findings {
		e.State.AddFinding(finding)
	}
}

// countAvailableChecks mirrors the ordering in vulncheck.Run closely enough to
// keep the terminal activity counter proportional without duplicating its
// internal state or changing the checks' behavior.
func countAvailableChecks(targets []vulncheck.Target) int {
	count := 0
	for _, target := range targets {
		for range target.Params {
			count += 4
		}
		count++
		if target.Login {
			count += 3
		}
		if count >= nativeCheckBudget {
			return nativeCheckBudget
		}
	}
	if count > nativeCheckBudget {
		return nativeCheckBudget
	}
	return count
}
