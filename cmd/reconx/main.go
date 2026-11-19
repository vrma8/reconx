// reconx is an authorization-gated, workspace-oriented reconnaissance CLI.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/vrma8/reconx/internal/config"
	"github.com/vrma8/reconx/internal/orchestrator"
	"github.com/vrma8/reconx/internal/report"
)

var version = "dev"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "reconx:", err)
		os.Exit(1)
	}
}

func run(arguments []string) error {
	if hasArgument(arguments, "--version") || hasArgument(arguments, "-version") {
		fmt.Println("reconx", version)
		return nil
	}
	settings := config.Default()
	configPath := configArgument(arguments)
	if configPath != "" {
		loaded, err := config.LoadFile(configPath, settings)
		if err != nil {
			return err
		}
		settings = loaded
	}
	flags := flag.NewFlagSet("reconx", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	flags.Usage = func() { usage(flags) }
	var targetFile string
	var noOSINT bool
	var noCloudAssets bool
	var noTakeoverVerify bool
	timeoutMS := int(settings.Timeout / time.Millisecond)
	flags.StringVar(&targetFile, "f", "", "file containing one target per line")
	flags.StringVar(&targetFile, "targets-file", "", "file containing one target per line")
	flags.BoolVar(&settings.Authorized, "i-am-authorized", false, "confirm you have authorization to assess the target (required)")
	flags.StringVar(&settings.Phases, "phases", settings.Phases, "comma-separated phase list/ranges, e.g. 0-4,6")
	flags.StringVar(&settings.Skip, "skip", "", "comma-separated phases to skip")
	flags.BoolVar(&settings.Fast, "fast", false, "fast mode: high-signal port list and capped wordlist")
	flags.BoolVar(&settings.Deep, "deep", false, "deep mode: all TCP ports and larger wordlists")
	flags.IntVar(&settings.Rate, "rate", settings.Rate, "maximum rate-limited network probes per second")
	flags.IntVar(&timeoutMS, "timeout", timeoutMS, "per-request timeout in milliseconds")
	flags.IntVar(&settings.Workers, "workers", settings.Workers, "concurrent worker count")
	flags.IntVar(&settings.Retries, "retries", settings.Retries, "retries after an initial network probe")
	flags.IntVar(&settings.MaxProbes, "max-probes", settings.MaxProbes, "probe budget before refusing a scan")
	flags.BoolVar(&settings.UnsafeLargeScan, "unsafe-large-scan", false, "allow scans exceeding max-probes")
	flags.BoolVar(&settings.Syn, "syn", false, "request SYN scan mode (currently TCP connect fallback)")
	flags.BoolVar(&settings.FullPorts, "full-ports", false, "scan TCP ports 1-65535")
	flags.BoolVar(&settings.UDP, "udp", false, "include responsive-UDP scan")
	flags.BoolVar(&settings.Masscan, "masscan", false, "use installed masscan pre-scan for large CIDRs")
	flags.BoolVar(&settings.ICMP, "icmp", false, "include bounded ICMP echo discovery for CIDR targets")
	flags.BoolVar(&settings.NmapServiceScan, "nmap-service-scan", false, "run nmap -sV --version-light on discovered TCP ports")
	flags.BoolVar(&settings.NmapOSScan, "nmap-os", false, "run nmap OS fingerprinting on discovered TCP hosts")
	flags.BoolVar(&settings.NmapVulnScan, "nmap-vuln", false, "run nmap's vuln NSE category on discovered TCP hosts")
	flags.BoolVar(&settings.ServiceEnum, "service-enum", false, "run read-only service-specific enumeration integrations")
	flags.BoolVar(&settings.ServiceDetails, "service-details", settings.ServiceDetails, "perform bounded protocol-specific banner/detail probes on open ports")
	flags.BoolVar(&settings.HostEnrichment, "host-enrichment", settings.HostEnrichment, "merge passive ASN/organization/country data into host inventory")
	flags.BoolVar(&settings.CloudAssets, "cloud-assets", settings.CloudAssets, "check bounded public cloud bucket candidates")
	flags.BoolVar(&settings.TakeoverVerify, "takeover-verify", settings.TakeoverVerify, "verify known CNAME takeover signatures with HTTP probes")
	flags.BoolVar(&noCloudAssets, "no-cloud-assets", false, "skip public cloud bucket candidate checks")
	flags.BoolVar(&noTakeoverVerify, "no-takeover-verify", false, "skip HTTP verification of known CNAME takeover signatures")
	flags.StringVar(&settings.NmapArgs, "nmap-args", "", "additional nmap arguments (passed without a shell)")
	flags.BoolVar(&settings.OSINT, "osint", settings.OSINT, "run local passive OSINT worker")
	flags.BoolVar(&noOSINT, "no-osint", false, "skip passive OSINT worker")
	flags.BoolVar(&settings.SubdomainBrute, "subdomain-brute", settings.SubdomainBrute, "perform DNS wordlist enumeration")
	flags.BoolVar(&settings.SubdomainPermutations, "subdomain-permutations", settings.SubdomainPermutations, "add bounded numeric and environment DNS permutations")
	flags.StringVar(&settings.SubdomainWordlist, "subdomain-wordlist", settings.SubdomainWordlist, "DNS subdomain wordlist path")
	flags.IntVar(&settings.SubdomainMaxWords, "max-subdomain-words", settings.SubdomainMaxWords, "maximum entries from each DNS wordlist source")
	flags.IntVar(&settings.SubdomainMaxPermutations, "max-subdomain-permutations", settings.SubdomainMaxPermutations, "maximum generated DNS permutation entries")
	flags.IntVar(&settings.CloudAssetMaxCandidates, "max-cloud-candidates", settings.CloudAssetMaxCandidates, "maximum cloud bucket/account candidates to check")
	flags.IntVar(&settings.TakeoverMaxChecks, "max-takeover-checks", settings.TakeoverMaxChecks, "maximum CNAME takeover candidates to inspect (0 means all, subject to max-probes)")
	flags.IntVar(&settings.CrawlDepth, "crawl-depth", settings.CrawlDepth, "same-scope crawl depth (0 disables)")
	flags.IntVar(&settings.MaxURLs, "max-urls", settings.MaxURLs, "maximum URLs per crawl seed")
	flags.BoolVar(&settings.RespectRobots, "respect-robots", settings.RespectRobots, "respect robots.txt when crawling")
	flags.BoolVar(&settings.ContentDiscovery, "content-discovery", false, "enable wordlist-based content discovery")
	flags.BoolVar(&settings.APIDiscovery, "api-discovery", settings.APIDiscovery, "probe common API and OpenAPI documentation paths")
	flags.StringVar(&settings.DirectoryWordlist, "directory-wordlist", settings.DirectoryWordlist, "content discovery wordlist path")
	flags.BoolVar(&settings.Screenshots, "screenshot", false, "capture screenshots with the optional Python Playwright helper")
	flags.BoolVar(&settings.JSAnalysis, "js-analysis", false, "run the optional Python JavaScript endpoint analyzer")
	flags.BoolVar(&settings.WAFDetection, "waf-detection", false, "run passive WAF signature checks and optional wafw00f")
	flags.BoolVar(&settings.HeaderScore, "header-score", settings.HeaderScore, "score observed HTTP security headers from 0-100")
	flags.BoolVar(&settings.SRIChecks, "sri-checks", settings.SRIChecks, "check external scripts/stylesheets for Subresource Integrity")
	flags.BoolVar(&settings.TLSAssessment, "tls-assessment", settings.TLSAssessment, "validate TLS hostname, chain, protocol and cipher policy")
	flags.BoolVar(&settings.ActiveWAF, "active-waf", false, "send bounded harmless payloads to look for WAF block signatures")
	flags.BoolVar(&settings.ParameterFuzzing, "parameter-fuzzing", false, "probe discovered parameters for reflection and error patterns")
	flags.BoolVar(&settings.SensitiveFiles, "sensitive-files", false, "probe a fixed set of high-signal sensitive paths")
	flags.StringVar(&settings.SensitiveWordlist, "sensitive-wordlist", settings.SensitiveWordlist, "optional wordlist for bounded sensitive-path HEAD probes")
	flags.IntVar(&settings.MaxSensitivePaths, "max-sensitive-paths", settings.MaxSensitivePaths, "maximum sensitive paths probed per seed")
	flags.BoolVar(&settings.TestSSL, "testssl", false, "run installed testssl.sh against discovered HTTPS URLs")
	flags.StringVar(&settings.ShodanKey, "shodan-key", settings.ShodanKey, "Shodan API key for optional external worker integrations")
	flags.StringVar(&settings.CensysKey, "censys-key", settings.CensysKey, "Censys bearer API key for the optional passive OSINT worker")
	flags.StringVar(&settings.CensysID, "censys-id", settings.CensysID, "Censys API ID for the optional passive OSINT worker")
	flags.StringVar(&settings.CensysSecret, "censys-secret", settings.CensysSecret, "Censys API secret for the optional passive OSINT worker")
	flags.StringVar(&settings.VTKey, "vt-key", settings.VTKey, "VirusTotal API key for optional external worker integrations")
	flags.StringVar(&settings.URLScanKey, "urlscan-key", settings.URLScanKey, "urlscan.io API key for optional external worker integrations")
	flags.StringVar(&settings.SerpKey, "serp-key", settings.SerpKey, "SerpAPI key for optional external worker integrations")
	flags.StringVar(&settings.GitHubToken, "github-token", settings.GitHubToken, "GitHub token for optional public code-search metadata")
	flags.StringVar(&settings.GitLabToken, "gitlab-token", settings.GitLabToken, "GitLab token for optional public code-search metadata")
	flags.StringVar(&settings.HIBPKey, "hibp-key", settings.HIBPKey, "Have I Been Pwned API key for discovered public email checks")
	flags.StringVar(&settings.SecurityTrailsKey, "securitytrails-key", settings.SecurityTrailsKey, "SecurityTrails API key for DNS history")
	flags.StringVar(&settings.ViewDNSKey, "viewdns-key", settings.ViewDNSKey, "ViewDNS API key for DNS history and reverse-IP checks")
	flags.StringVar(&settings.IPInfoToken, "ipinfo-token", settings.IPInfoToken, "ipinfo token for ASN and ownership metadata")
	flags.BoolVar(&settings.OSINTAXFR, "axfr", settings.OSINTAXFR, "attempt bounded DNS zone transfers against authoritative nameservers")
	flags.BoolVar(&settings.SocialEnum, "social-enum", settings.SocialEnum, "run installed sherlock for discovered public email local-parts")
	flags.BoolVar(&settings.ActiveChecks, "active-checks", false, "run bounded native web checks (traversal, XSS, SSRF, IDOR, auth bypass, default credentials)")
	flags.BoolVar(&settings.Nuclei, "nuclei", false, "run installed nuclei templates (explicit opt-in)")
	flags.BoolVar(&settings.Nikto, "nikto", false, "run installed Nikto (explicit opt-in)")
	flags.BoolVar(&settings.SQLMap, "sqlmap", false, "run installed sqlmap on discovered query URLs (explicit opt-in)")
	flags.BoolVar(&settings.WPScan, "wpscan", false, "run installed WPScan on discovered web URLs (explicit opt-in)")
	flags.BoolVar(&settings.NVD, "nvd", false, "match detected service banners against a local NVD JSON feed")
	flags.StringVar(&settings.CVEDB, "cve-db", settings.CVEDB, "path to a local NVD JSON feed used with --nvd")
	flags.BoolVar(&settings.NLP, "nlp", settings.NLP, "extract non-secret entity indicators from fetched content")
	flags.StringVar(&settings.Workspace, "workspace", settings.Workspace, "workspace directory")
	flags.StringVar(&settings.HTML, "html", "", "write HTML report to this file")
	flags.StringVar(&settings.JSON, "json", "", "write JSON report to this file")
	flags.StringVar(&settings.CSV, "csv", "", "write CSV findings to this file")
	flags.StringVar(&settings.PDF, "pdf", "", "write PDF report using wkhtmltopdf")
	flags.BoolVar(&settings.SystemdUnit, "systemd-unit", false, "write optional systemd service/timer units for scheduled scans")
	flags.StringVar(&settings.Diff, "diff", "", "previous workspace or report.json to diff")
	flags.BoolVar(&settings.ShowSecrets, "show-secrets", false, "include detected secret values in workspace/export evidence")
	flags.StringVar(&configPath, "config", configPath, "YAML configuration file")
	flags.StringVar(&settings.PythonDir, "python-dir", settings.PythonDir, "directory containing optional Python modules")
	flags.BoolVar(&settings.Verbose, "verbose", false, "enable debug logs")
	flags.BoolVar(&settings.Quiet, "quiet", false, "only log errors")
	// The documented CLI puts the target first, while flag.Parse stops at the
	// first positional argument. Move options ahead of positional targets so
	// both `reconx target --flag` and `reconx --flag target` work.
	if err := flags.Parse(normalizeArguments(flags, arguments)); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	settings.Timeout = time.Duration(timeoutMS) * time.Millisecond
	if noOSINT {
		settings.OSINT = false
	}
	if noCloudAssets {
		settings.CloudAssets = false
	}
	if noTakeoverVerify {
		settings.TakeoverVerify = false
	}
	if settings.Deep {
		settings.FullPorts = true
		settings.ContentDiscovery = true
		settings.SubdomainPermutations = true
		settings.JSAnalysis = true
		settings.Nuclei = true
		settings.SQLMap = true
		settings.WPScan = true
		settings.ServiceDetails = true
		settings.SensitiveFiles = true
		settings.ParameterFuzzing = true
		settings.ActiveWAF = true
	}
	if err := settings.Validate(); err != nil {
		return err
	}
	targets, err := targets(flags.Args(), targetFile)
	if err != nil {
		return err
	}
	if !settings.Authorized {
		return errors.New("--i-am-authorized is required; only scan systems you are permitted to assess")
	}
	if len(targets) > 1 && settings.Workspace != "" {
		return errors.New("--workspace can only be used with one target; use default per-target workspaces for a target file")
	}
	level := slog.LevelInfo
	if settings.Verbose {
		level = slog.LevelDebug
	}
	if settings.Quiet {
		level = slog.LevelError
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	for _, target := range targets {
		engine, err := orchestrator.New(target, settings, logger)
		if err != nil {
			return err
		}
		reportValue, runErr := engine.Run(ctx)
		report.TerminalDetailed(os.Stdout, reportValue, !settings.Quiet, !settings.Quiet)
		fmt.Printf("Workspace: %s\n", engine.Workspace.Root)
		if runErr != nil {
			return runErr
		}
	}
	return nil
}

func targets(arguments []string, file string) ([]string, error) {
	if file == "" {
		if len(arguments) != 1 {
			return nil, errors.New("provide exactly one target or use -f targets.txt")
		}
		return []string{arguments[0]}, nil
	}
	if len(arguments) != 0 {
		return nil, errors.New("do not combine a positional target with -f")
	}
	handle, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer handle.Close()
	result, seen := make([]string, 0), map[string]struct{}{}
	scanner := bufio.NewScanner(handle)
	for scanner.Scan() {
		target := strings.TrimSpace(strings.SplitN(scanner.Text(), "#", 2)[0])
		if target != "" {
			if _, found := seen[target]; !found {
				seen[target] = struct{}{}
				result = append(result, target)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(result) == 0 {
		return nil, errors.New("target file contains no targets")
	}
	return result, nil
}

// normalizeArguments keeps each option next to its value while moving
// positional targets after all options. Bool flags that implement IsBoolFlag
// do not consume the following token, which matches flag package semantics.
func normalizeArguments(flags *flag.FlagSet, arguments []string) []string {
	options := make([]string, 0, len(arguments))
	positional := make([]string, 0, 1)
	for index := 0; index < len(arguments); index++ {
		argument := arguments[index]
		if argument == "--" {
			positional = append(positional, arguments[index+1:]...)
			break
		}
		if !strings.HasPrefix(argument, "-") || argument == "-" {
			positional = append(positional, argument)
			continue
		}
		name := strings.TrimLeft(argument, "-")
		if strings.Contains(name, "=") {
			options = append(options, argument)
			continue
		}
		option := flags.Lookup(name)
		if option != nil {
			if _, boolean := option.Value.(interface{ IsBoolFlag() bool }); !boolean && index+1 < len(arguments) {
				index++
				options = append(options, argument, arguments[index])
				continue
			}
		}
		options = append(options, argument)
	}
	return append(options, positional...)
}

func configArgument(arguments []string) string {
	for index, value := range arguments {
		if value == "--config" && index+1 < len(arguments) {
			return arguments[index+1]
		}
		if strings.HasPrefix(value, "--config=") {
			return strings.TrimPrefix(value, "--config=")
		}
	}
	return ""
}
func hasArgument(arguments []string, needle string) bool {
	for _, value := range arguments {
		if value == needle {
			return true
		}
	}
	return false
}
func usage(flags *flag.FlagSet) {
	fmt.Fprint(flags.Output(), "Usage: reconx <IP|CIDR|domain|URL> --i-am-authorized [options]\n\nreconx is an authorization-gated reconnaissance tool. It uses bounded workers, a global probe rate, and a probe budget.\n\n")
	flags.PrintDefaults()
}
