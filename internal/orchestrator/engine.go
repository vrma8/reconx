// Package orchestrator wires reconx phases together. Each phase is isolated:
// a failure is recorded as a warning and later phases retain partial results.
package orchestrator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/vrma8/reconx/internal/assets"
	"github.com/vrma8/reconx/internal/cloud"
	"github.com/vrma8/reconx/internal/config"
	"github.com/vrma8/reconx/internal/cve"
	"github.com/vrma8/reconx/internal/dns"
	"github.com/vrma8/reconx/internal/enrich"
	"github.com/vrma8/reconx/internal/external"
	"github.com/vrma8/reconx/internal/httpx"
	"github.com/vrma8/reconx/internal/model"
	"github.com/vrma8/reconx/internal/report"
	"github.com/vrma8/reconx/internal/scanner"
	"github.com/vrma8/reconx/internal/scoring"
	"github.com/vrma8/reconx/internal/secrets"
	"github.com/vrma8/reconx/internal/services"
	"github.com/vrma8/reconx/internal/utils"
)

var phaseNames = map[int]string{0: "Target intake", 1: "Passive OSINT", 2: "Subdomain enumeration", 3: "Host discovery", 4: "Port scanning", 5: "Service enumeration", 6: "Web reconnaissance", 7: "Vulnerability checks", 8: "Secrets extraction", 9: "Risk scoring", 10: "Report generation"}

type Engine struct {
	Config      config.Config
	Workspace   *Workspace
	State       *model.State
	parsed      utils.ParsedTarget
	logger      *slog.Logger
	risk        model.RiskSummary
	stats       model.RunStats
	screenshots []model.ScreenshotRef
}

func New(target string, settings config.Config, logger *slog.Logger) (*Engine, error) {
	if err := settings.Validate(); err != nil {
		return nil, err
	}
	parsed, err := utils.ParseTarget(target)
	if err != nil {
		return nil, err
	}
	if logger == nil {
		logger = slog.Default()
	}
	workspace, err := NewWorkspace(settings.Workspace, target)
	if err != nil {
		return nil, err
	}
	return &Engine{Config: settings, Workspace: workspace, parsed: parsed, logger: logger}, nil
}

func (e *Engine) Run(ctx context.Context) (model.Report, error) {
	if !e.Config.Authorized {
		return model.Report{}, errors.New("refusing to run: pass --i-am-authorized only for targets you are authorized to assess")
	}
	profile, err := utils.ResolveTarget(ctx, e.parsed)
	if err != nil && profile.Kind != model.TargetCIDR {
		return model.Report{}, err
	}
	e.State = model.NewState(profile)
	e.checkRequestedTools()
	if profile.Hostname != "" {
		e.State.AddSubdomain(profile.Hostname)
	}
	for _, value := range profile.IPs {
		if address, parseErr := netip.ParseAddr(value); parseErr == nil {
			e.State.AddHost(address, profile.Hostname)
		}
	}
	selected, err := phaseSelection(e.Config.Phases, e.Config.Skip)
	if err != nil {
		return model.Report{}, err
	}
	for phase := 0; phase <= 10; phase++ {
		if !selected[phase] {
			continue
		}
		started := time.Now()
		result := model.PhaseResult{Number: phase, Name: phaseNames[phase], Status: "done"}
		err := e.runPhase(ctx, phase)
		if err == nil && ctx.Err() != nil {
			err = ctx.Err()
		}
		result.Duration = time.Since(started)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				result.Status, result.Warning = "cancelled", err.Error()
				e.State.AddPhase(result)
				_ = e.Workspace.WriteJSON("run_state.json", e.buildReport())
				return e.buildReport(), err
			}
			result.Status, result.Warning = "warning", err.Error()
			e.State.AddWarning(fmt.Sprintf("phase %d (%s): %s", phase, result.Name, err))
			e.logger.Warn("phase completed with warning", "phase", phase, "name", result.Name, "error", err)
		} else if !e.Config.Quiet {
			e.logger.Info("phase complete", "phase", phase, "name", result.Name, "duration", result.Duration.Round(time.Millisecond))
		}
		e.State.AddPhase(result)
		_ = e.Workspace.WriteJSON("run_state.json", e.buildReport())
		if phase == 10 && err == nil {
			// Phase 10 serializes before the runner records its own result.
			// Rewrite the exports once so reports include the final phase row.
			_ = e.writeReports(e.buildReport())
		}
	}
	return e.buildReport(), nil
}

func (e *Engine) checkRequestedTools() {
	requested := map[string]bool{
		"masscan":    e.Config.Masscan,
		"nmap":       e.Config.NmapServiceScan || e.Config.NmapOSScan || e.Config.NmapVulnScan || e.Config.ServiceEnum,
		"nuclei":     e.Config.Nuclei,
		"nikto":      e.Config.Nikto,
		"sqlmap":     e.Config.SQLMap,
		"wpscan":     e.Config.WPScan,
		"testssl.sh": e.Config.TestSSL,
		"wafw00f":    e.Config.WAFDetection,
		"sherlock":   e.Config.SocialEnum,
	}
	tools := make([]string, 0, len(requested))
	for tool, enabled := range requested {
		if enabled {
			tools = append(tools, tool)
		}
	}
	sort.Strings(tools)
	for _, tool := range tools {
		if _, err := e.lookupTool(tool); err != nil {
			e.State.AddWarning(tool + " is requested but unavailable; affected sub-phases will be skipped")
		}
	}
}

func (e *Engine) runPhase(ctx context.Context, phase int) error {
	switch phase {
	case 0:
		return e.phase0()
	case 1:
		return e.phase1(ctx)
	case 2:
		return e.phase2(ctx)
	case 3:
		return e.phase3(ctx)
	case 4:
		return e.phase4(ctx)
	case 5:
		return e.phase5(ctx)
	case 6:
		return e.phase6(ctx)
	case 7:
		return e.phase7(ctx)
	case 8:
		return e.phase8(ctx)
	case 9:
		return e.phase9()
	case 10:
		return e.phase10()
	default:
		return fmt.Errorf("unknown phase %d", phase)
	}
}

func (e *Engine) phase0() error {
	profile, _, _, _, _, _, _ := e.State.Snapshot()
	if err := e.Workspace.WriteJSON("target_profile.json", profile); err != nil {
		return err
	}
	return e.Workspace.WriteJSON("03_hosts/host_inventory.json", e.State.HostList())
}

func (e *Engine) phase1(ctx context.Context) error {
	profile, _, _, _, _, _, _ := e.State.Snapshot()
	result := osintOutput{Target: profile.Hostname}
	if profile.Hostname != "" {
		record := dns.Records(ctx, profile.Hostname)
		e.State.AddDNS(record)
		result.DNS = record
	}
	if e.Config.OSINT {
		pythonResult, err := e.pythonOSINT(ctx, profile)
		if err != nil {
			e.State.AddWarning("Python OSINT module unavailable: " + err.Error())
		} else {
			result = mergeOSINT(result, pythonResult)
			for _, name := range result.Subdomains {
				if profile.Hostname == "" || utils.IsSubdomainOrEqual(name, profile.Hostname) {
					e.State.AddSubdomain(name)
				}
			}
		}
	}
	result.Subdomains = utils.Strings(result.Subdomains)
	if result.DNS.Name != "" {
		e.State.AddDNS(result.DNS)
	}
	for _, warning := range result.Warnings {
		e.State.AddWarning("OSINT " + warning)
	}
	if err := e.Workspace.WriteJSON("01_osint/osint_results.json", result); err != nil {
		return err
	}
	if err := e.Workspace.WriteText("01_osint/subdomains_passive.txt", strings.Join(result.Subdomains, "\n")+trailingNewline(result.Subdomains)); err != nil {
		return err
	}
	if err := e.Workspace.WriteText("01_osint/emails.txt", strings.Join(result.Emails, "\n")+trailingNewline(result.Emails)); err != nil {
		return err
	}
	secretLines := osintSecretLines(result.SecretIndicators)
	if err := e.Workspace.WriteText("01_osint/secrets_found.txt", strings.Join(secretLines, "\n")+trailingNewline(secretLines)); err != nil {
		return err
	}
	if err := e.Workspace.WriteJSON("01_osint/tech_stack.json", result.TechStack); err != nil {
		return err
	}
	if err := os.MkdirAll(e.Workspace.Path("01_osint", "screenshots"), 0o750); err != nil {
		return err
	}
	if e.Config.HostEnrichment {
		e.enrichHostsFromOSINT()
	}
	return e.Workspace.WriteJSON("01_osint/screenshots/manifest.json", result.Screenshots)
}

// enrichHostsFromOSINT merges the passive network-ownership data already
// collected by Phase 1 into the host inventory. It performs no new requests.
func (e *Engine) enrichHostsFromOSINT() {
	content, err := os.ReadFile(e.Workspace.Path("01_osint", "osint_results.json"))
	if err != nil {
		return
	}
	var payload struct {
		Sources map[string]json.RawMessage `json:"sources"`
	}
	if err := json.Unmarshal(content, &payload); err != nil {
		return
	}
	raw, found := payload.Sources["network_ownership"]
	if !found {
		return
	}
	var ownership map[string]json.RawMessage
	if err := json.Unmarshal(raw, &ownership); err != nil {
		return
	}
	type ownershipEntry struct {
		IPInfo struct {
			ASN     string `json:"asn"`
			Org     string `json:"org"`
			Country string `json:"country"`
		} `json:"ipinfo"`
		BGP map[string]any `json:"bgp_tools"`
	}
	for address, rawEntry := range ownership {
		var entry ownershipEntry
		if err := json.Unmarshal(rawEntry, &entry); err != nil {
			continue
		}
		asn := entry.IPInfo.ASN
		if asn == "" {
			asn = stringValue(entry.BGP["asn"])
		}
		if asn == "" && entry.IPInfo.Org == "" && entry.IPInfo.Country == "" {
			continue
		}
		e.State.AddHostEnrichment(address, asn, entry.IPInfo.Org, entry.IPInfo.Country)
	}
}

func stringValue(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case float64:
		return strconv.FormatInt(int64(typed), 10)
	default:
		return ""
	}
}

func (e *Engine) phase2(ctx context.Context) error {
	profile, _, _, _, _, _, _ := e.State.Snapshot()
	if profile.Hostname == "" {
		return e.writeEmptySubdomains()
	}

	// Passive names are already present in State. Active enumeration is kept
	// rate-limited and budgeted separately so a large custom wordlist cannot
	// turn a convenience flag into unbounded DNS traffic.
	passiveNames := e.State.SubdomainList()
	enumerationProbes := 0
	if e.Config.SubdomainBrute || e.Config.SubdomainPermutations || e.Config.Deep {
		words, err := e.subdomainWords()
		if err != nil {
			e.State.AddWarning("subdomain wordlist: " + err.Error())
		} else {
			permutations := []string{}
			if e.Config.SubdomainPermutations || e.Config.Deep {
				seeds := append(words, subdomainLabels(profile.Hostname, passiveNames)...)
				permutations = subdomainPermutations(seeds, e.subdomainPermutationLimit())
			}
			candidateCount := len(permutations)
			if e.Config.SubdomainBrute {
				candidateCount += len(words)
			}
			enumerationProbes = candidateCount
			if err := e.checkProbeBudget(1, candidateCount); err != nil {
				return fmt.Errorf("phase 2 DNS enumeration: %w", err)
			}
			if e.Config.SubdomainBrute {
				for _, name := range dns.BruteRateLimited(ctx, profile.Hostname, words, e.Config.Workers, e.Config.Rate) {
					e.State.AddSubdomain(name)
				}
			}
			if len(permutations) > 0 {
				for _, name := range dns.BruteRateLimited(ctx, profile.Hostname, permutations, e.Config.Workers, e.Config.Rate) {
					e.State.AddSubdomain(name)
				}
			}
		}
	}

	names := e.State.SubdomainList()
	// Reserve the complete Phase-2 budget before any resolution, CNAME, cloud,
	// or takeover HTTP work begins. GET fallbacks are included pessimistically,
	// so a method-rejecting provider cannot quietly exceed --max-probes.
	cnameChecks := len(names)
	if e.Config.TakeoverMaxChecks > 0 && cnameChecks > e.Config.TakeoverMaxChecks {
		cnameChecks = e.Config.TakeoverMaxChecks
	}
	cloudChecks := 0
	if e.Config.CloudAssets {
		cloudChecks = len(cloud.Candidates(names, e.Config.CloudAssetMaxCandidates))
	}
	takeoverHTTPChecks := 0
	if e.Config.TakeoverVerify {
		takeoverHTTPChecks = cnameChecks * 2
	}
	phase2Probes := enumerationProbes + len(names) + cnameChecks + cloudChecks*2 + takeoverHTTPChecks
	e.stats.DNSQueries += enumerationProbes + len(names) + cnameChecks
	e.stats.HTTPRequests += cloudChecks*2 + takeoverHTTPChecks
	if err := e.checkProbeBudget(1, phase2Probes); err != nil {
		return fmt.Errorf("phase 2 attack-surface probes: %w", err)
	}
	previous, previousErr := e.previousSubdomains()
	if previousErr != nil {
		e.State.AddWarning("previous subdomain inventory: " + previousErr.Error())
	}
	resolved := dns.ResolveManyRateLimited(ctx, names, e.Config.Workers, e.Config.Rate)
	serialized := make(map[string][]string, len(names))
	allIPs := make([]string, 0)
	for _, name := range names {
		addresses := resolved[name]
		values := make([]string, 0, len(addresses))
		for _, address := range addresses {
			values = append(values, address.String())
			allIPs = append(allIPs, address.String())
			e.State.AddHost(address, name)
		}
		sort.Strings(values)
		serialized[name] = values
	}
	allIPs = sortedUnique(allIPs)
	takeovers := e.detectPotentialTakeovers(ctx, names)
	if e.Config.TakeoverVerify {
		takeovers = e.verifyTakeovers(ctx, takeovers)
	}
	newNames := make([]string, 0)
	for _, name := range names {
		if _, found := previous[name]; !found {
			newNames = append(newNames, name)
		}
	}
	if err := e.Workspace.WriteText("02_subdomains/all_subdomains.txt", strings.Join(names, "\n")+trailingNewline(names)); err != nil {
		return err
	}
	if err := e.Workspace.WriteText("02_subdomains/all_ips.txt", strings.Join(allIPs, "\n")+trailingNewline(allIPs)); err != nil {
		return err
	}
	if err := e.Workspace.WriteJSON("02_subdomains/subdomain_ips.json", serialized); err != nil {
		return err
	}
	if err := e.Workspace.WriteText("02_subdomains/new_subdomains.txt", strings.Join(newNames, "\n")+trailingNewline(newNames)); err != nil {
		return err
	}
	assets := []cloud.Result{}
	if e.Config.CloudAssets {
		assets = e.checkCloudAssets(ctx, names)
	}
	if err := e.Workspace.WriteJSON("02_subdomains/cloud_assets.json", assets); err != nil {
		return err
	}
	return e.Workspace.WriteJSON("02_subdomains/takeovers.json", takeovers)
}

func (e *Engine) phase3(ctx context.Context) error {
	profile, hosts, _, _, _, _, _ := e.State.Snapshot()
	if profile.Kind == model.TargetCIDR {
		addresses, err := utils.CIDRAddresses(e.parsed.Prefix, e.Config.MaxProbes)
		if err != nil {
			return err
		}
		livePorts := []int{22, 80, 443, 3389}
		if err := e.checkProbeBudget(len(addresses), len(livePorts)+boolInt(e.Config.ICMP)); err != nil {
			return err
		}
		if e.Config.ICMP {
			for _, address := range e.icmpSweep(ctx, addresses) {
				e.State.AddHost(address, "")
				e.State.MarkReachable(address.String())
			}
		}
		results, err := scanner.ScanTCP(ctx, addresses, livePorts, e.scanOptions())
		if err != nil && !errors.Is(err, context.Canceled) {
			return err
		}
		for _, result := range results {
			e.State.AddOpenPort(result.Host, result.Port, false)
		}
		hosts = e.State.HostList()
	}
	for _, host := range hosts {
		name, err := net.DefaultResolver.LookupAddr(ctx, host.IP)
		if err == nil && len(name) > 0 {
			e.State.SetReverseDNS(host.IP, strings.TrimSuffix(name[0], "."))
		}
	}
	hosts = e.State.HostList()
	live := make([]string, 0, len(hosts))
	for _, host := range hosts {
		if host.Reachable || profile.Kind != model.TargetCIDR {
			live = append(live, host.IP)
		}
	}
	if err := e.Workspace.WriteText("03_hosts/live_hosts.txt", strings.Join(live, "\n")+trailingNewline(live)); err != nil {
		return err
	}
	if err := e.Workspace.WriteText("03_hosts/arp_results.txt", "ARP discovery is not available in this portable CGO-free build.\n"); err != nil {
		return err
	}
	return e.Workspace.WriteJSON("03_hosts/host_inventory.json", hosts)
}

func (e *Engine) phase4(ctx context.Context) error {
	hosts := e.State.HostList()
	addresses := hostAddresses(hosts)
	if len(addresses) == 0 {
		return errors.New("no resolved hosts available for port scanning")
	}
	ports := scanner.Ports(e.Config.FullPorts || e.Config.Deep, e.Config.Fast)
	if err := e.checkProbeBudget(len(addresses), len(ports)); err != nil {
		return err
	}
	if e.Config.Syn {
		e.State.AddWarning("SYN mode requires a privileged AF_PACKET implementation and currently falls back to TCP connect scanning")
	}
	var results []scanner.Result
	var err error
	if e.Config.Masscan && e.parsed.Profile.Kind == model.TargetCIDR {
		results, err = e.masscanPreScan(ctx)
		if err != nil {
			e.State.AddWarning("masscan pre-scan: " + err.Error())
		}
	}
	if len(results) > 0 {
		results, err = scanner.ScanTCPPairs(ctx, results, e.scanOptions())
	} else {
		results, err = scanner.ScanTCP(ctx, addresses, ports, e.scanOptions())
	}
	if err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	e.stats.Probes += len(addresses) * len(ports)
	for _, result := range results {
		e.State.AddOpenPort(result.Host, result.Port, false)
	}
	if e.Config.UDP {
		if err := e.checkProbeBudget(len(addresses), len(scanner.TopUDPPorts)); err != nil {
			return err
		}
		e.stats.Probes += len(addresses) * len(scanner.TopUDPPorts)
		udp, udpErr := scanner.ScanUDP(ctx, addresses, scanner.TopUDPPorts, e.scanOptions())
		if udpErr != nil && !errors.Is(udpErr, context.Canceled) {
			e.State.AddWarning("UDP scan: " + udpErr.Error())
		}
		for _, result := range udp {
			e.State.AddOpenPort(result.Host, result.Port, true)
		}
	}
	e.enumerateServices(ctx)
	hosts = e.State.HostList()
	services := make([]model.Service, 0)
	for _, host := range hosts {
		services = append(services, host.Services...)
	}
	if err := e.Workspace.WriteJSON("04_ports/open_tcp.json", hosts); err != nil {
		return err
	}
	if err := e.Workspace.WriteJSON("04_ports/open_udp.json", hosts); err != nil {
		return err
	}
	if err := e.Workspace.WriteJSON("04_ports/ports.json", hosts); err != nil {
		return err
	}
	if err := e.Workspace.WriteJSON("04_ports/services.json", services); err != nil {
		return err
	}
	return e.Workspace.WriteJSON("04_ports/os_fingerprints.json", []any{})
}

type serviceDetail struct {
	Host    string `json:"host"`
	Port    int    `json:"port"`
	Service string `json:"service"`
	Tool    string `json:"tool"`
	Output  string `json:"output,omitempty"`
	Error   string `json:"error,omitempty"`
}

func (e *Engine) phase5(ctx context.Context) error {
	details := make([]serviceDetail, 0)
	operatingSystems := map[string]string{}
	if e.Config.NmapServiceScan || e.Config.NmapOSScan || e.Config.NmapVulnScan {
		tool, err := e.lookupTool("nmap")
		if err != nil {
			e.State.AddWarning("nmap requested but not installed")
		} else {
			for _, host := range e.State.HostList() {
				if len(host.OpenTCP) == 0 {
					continue
				}
				ports := make([]string, len(host.OpenTCP))
				for i, port := range host.OpenTCP {
					ports[i] = strconv.Itoa(port)
				}
				arguments := []string{"-Pn", "-p", strings.Join(ports, ","), "-oX", "-"}
				if e.Config.NmapServiceScan {
					arguments = append(arguments, "-sV", "--version-light")
				}
				if e.Config.NmapOSScan {
					arguments = append(arguments, "-O")
				}
				if e.Config.NmapVulnScan {
					arguments = append(arguments, "--script", "vuln")
				}
				arguments = append(arguments, strings.Fields(e.Config.NmapArgs)...)
				arguments = append(arguments, host.IP)
				e.stats.ToolInvocations++
				command := exec.CommandContext(ctx, tool, arguments...)
				output, commandErr := command.CombinedOutput()
				name := filepath.Join("05_services", strings.ReplaceAll(host.IP, ":", "_")+"_nmap.xml")
				if writeErr := e.Workspace.WriteBytes(name, output); writeErr != nil {
					return writeErr
				}
				detail := serviceDetail{Host: host.IP, Service: "nmap", Tool: "nmap", Output: name}
				if commandErr != nil {
					detail.Error = commandErr.Error()
					e.State.AddWarning(fmt.Sprintf("nmap %s: %v", host.IP, commandErr))
				}
				details = append(details, detail)
				parsedServices, detectedOS, parseErr := enrich.ParseNmapXML(bytes.NewReader(output))
				if parseErr != nil {
					e.State.AddWarning("parse nmap XML for " + host.IP + ": " + parseErr.Error())
					continue
				}
				for _, parsed := range parsedServices {
					e.State.MergeService(parsed)
				}
				for address, description := range detectedOS {
					operatingSystems[address] = description
				}
			}
		}
	}
	if e.Config.ServiceEnum {
		details = append(details, e.enumerateExternalServices(ctx)...)
	}
	if err := e.Workspace.WriteJSON("04_ports/os_fingerprints.json", operatingSystems); err != nil {
		return err
	}
	if err := e.Workspace.WriteJSON("05_services/service_details.json", details); err != nil {
		return err
	}
	return e.Workspace.WriteText("05_services/README.txt", "Native banner/TLS and protocol details are recorded in Phase 4. Optional external tool output is captured as raw, untrusted data and normalized into service metadata when parseable.\n")
}

func (e *Engine) enumerateExternalServices(ctx context.Context) []serviceDetail {
	details := make([]serviceDetail, 0)
	for _, host := range e.State.HostList() {
		for _, service := range host.Services {
			var tool string
			var arguments []string
			switch service.Name {
			case "smb":
				if _, err := e.lookupTool("enum4linux"); err == nil {
					tool, arguments = "enum4linux", []string{"-a", host.IP}
				} else {
					tool, arguments = "smbclient", []string{"-L", "//" + host.IP, "-N", "-m", "SMB3"}
				}
			case "ldap":
				scheme := "ldap"
				if service.TLS {
					scheme = "ldaps"
				}
				tool, arguments = "ldapsearch", []string{"-x", "-H", fmt.Sprintf("%s://%s:%d", scheme, host.IP, service.Port), "-b", "", "-s", "base"}
			case "snmp":
				tool, arguments = "snmpwalk", []string{"-v2c", "-c", "public", "-t", "1", "-r", "0", host.IP, "1.3.6.1.2.1.1"}
			case "ftp":
				tool, arguments = "nmap", []string{"-Pn", "-p", strconv.Itoa(service.Port), "--script", "ftp-anon", host.IP}
			default:
				continue
			}
			binary, err := e.lookupTool(tool)
			detail := serviceDetail{Host: host.IP, Port: service.Port, Service: service.Name, Tool: tool}
			if err != nil {
				detail.Error = tool + " is not installed"
				details = append(details, detail)
				continue
			}
			command := exec.CommandContext(ctx, binary, arguments...)
			output, commandErr := command.CombinedOutput()
			name := filepath.Join("05_services", safeName(host.IP+"_"+strconv.Itoa(service.Port)+"_"+tool)+".txt")
			if writeErr := e.Workspace.WriteBytes(name, output); writeErr != nil {
				detail.Error = writeErr.Error()
				details = append(details, detail)
				continue
			}
			detail.Output = name
			if commandErr != nil {
				detail.Error = commandErr.Error()
			}
			details = append(details, detail)
		}
	}
	return details
}

func (e *Engine) phase6(ctx context.Context) error {
	profile, hosts, _, _, _, _, _ := e.State.Snapshot()
	probes := e.webTargets(profile, hosts)
	client := httpx.New(e.Config.Timeout, e.Config.UserAgent)
	e.stats.HTTPRequests += len(probes)
	results := parallelProbe(ctx, client, probes, e.Config.Workers)
	for _, result := range results {
		if result.Error == "" {
			e.State.AddWeb(result)
			e.addWebFindings(result)
		}
	}
	if e.Config.CrawlDepth > 0 && profile.Hostname != "" {
		for _, result := range results {
			if result.Error != "" || result.StatusCode == 0 || result.StatusCode >= 500 {
				continue
			}
			disallowed := []string(nil)
			if e.Config.RespectRobots {
				if parsed, err := url.Parse(result.FinalURL); err == nil {
					robots := client.Probe(ctx, (&url.URL{Scheme: parsed.Scheme, Host: parsed.Host, Path: "/robots.txt"}).String())
					if robots.Error == "" && robots.StatusCode == 200 {
						disallowed = httpx.RobotsDisallows(robots.Body)
					}
				}
			}
			for _, crawled := range client.Crawl(ctx, result.FinalURL, profile.Hostname, e.Config.CrawlDepth, e.Config.MaxURLs, min(e.Config.Workers, 20), disallowed) {
				if crawled.Error == "" {
					e.State.AddWeb(crawled)
					e.addWebFindings(crawled)
				}
			}
		}
	}
	if e.Config.ContentDiscovery {
		e.contentDiscovery(ctx, client, results)
	}
	if e.Config.APIDiscovery {
		e.discoverAPI(ctx, client, results)
	}
	_, _, _, web, _, _, _ := e.State.Snapshot()
	fingerprints := make(map[string][]string, len(web))
	headers := make(map[string]map[string]string, len(web))
	tlsResults := make(map[string]*model.TLSInfo, len(web))
	forms := make(map[string][]model.WebForm, len(web))
	parameters := make(map[string][]string)
	endpoints := make([]string, 0)
	for _, result := range web {
		fingerprints[result.FinalURL] = result.Technologies
		headers[result.FinalURL] = result.Headers
		if result.TLS != nil {
			tlsResults[result.FinalURL] = result.TLS
		}
		if len(result.Forms) > 0 {
			forms[result.FinalURL] = result.Forms
			for _, form := range result.Forms {
				action := form.Action
				if parsedAction, err := url.Parse(form.Action); err == nil {
					if base, err := url.Parse(result.FinalURL); err == nil {
						action = base.ResolveReference(parsedAction).String()
					}
				}
				if action != "" {
					parameters[action] = append(parameters[action], form.Fields...)
				}
			}
		}
		if parsed, err := url.Parse(result.FinalURL); err == nil {
			for key := range parsed.Query() {
				parameters[result.FinalURL] = append(parameters[result.FinalURL], key)
			}
		}
		endpoints = append(endpoints, result.APIEndpoints...)
	}
	for target, values := range parameters {
		parameters[target] = sortedUnique(values)
	}
	endpoints = sortedUnique(endpoints)
	directories := make([]string, 0)
	for _, result := range web {
		if parsed, err := url.Parse(result.FinalURL); err == nil && parsed.Path != "" && parsed.Path != "/" && result.StatusCode <= 500 {
			directories = append(directories, result.FinalURL)
		}
	}
	directories = sortedUnique(directories)
	jsResults := []jsAnalysisResult{}
	if e.Config.JSAnalysis {
		jsResults = e.analyzeJavaScript(ctx, web)
		for _, result := range jsResults {
			endpoints = append(endpoints, result.Endpoints...)
		}
		endpoints = sortedUnique(endpoints)
	}
	if err := e.runEnhancedWebChecks(ctx, client, web, parameters); err != nil {
		return err
	}
	waf := detectWAF(web)
	openAPI := extractOpenAPI(web)
	screenshots := []screenshotResult{}
	if e.Config.Screenshots {
		screenshots = e.captureScreenshots(ctx, web)
		for _, screenshot := range screenshots {
			if screenshot.Path == "" {
				continue
			}
			e.screenshots = append(e.screenshots, model.ScreenshotRef{URL: screenshot.URL, Path: screenshot.Path, Name: filepath.Base(screenshot.Path)})
		}
	}
	if e.Config.WAFDetection {
		e.runWAFW00F(ctx, web)
	}
	if e.Config.TestSSL {
		e.runTestSSL(ctx, web)
	}
	if err := e.Workspace.WriteJSON("06_web/web_results.json", web); err != nil {
		return err
	}
	if err := e.Workspace.WriteJSON("06_web/web_fingerprints.json", fingerprints); err != nil {
		return err
	}
	if err := e.Workspace.WriteJSON("06_web/crawl_results.json", web); err != nil {
		return err
	}
	if err := e.Workspace.WriteJSON("06_web/api_endpoints.json", endpoints); err != nil {
		return err
	}
	if err := e.Workspace.WriteText("06_web/directories_found.txt", strings.Join(directories, "\n")+trailingNewline(directories)); err != nil {
		return err
	}
	if err := e.Workspace.WriteJSON("06_web/forms.json", forms); err != nil {
		return err
	}
	if err := e.Workspace.WriteJSON("06_web/parameters.json", parameters); err != nil {
		return err
	}
	if err := e.Workspace.WriteJSON("06_web/security_headers.json", headers); err != nil {
		return err
	}
	if err := e.Workspace.WriteJSON("06_web/tls_analysis.json", tlsResults); err != nil {
		return err
	}
	if err := e.Workspace.WriteJSON("06_web/js_analysis.json", jsResults); err != nil {
		return err
	}
	if err := e.Workspace.WriteJSON("06_web/waf.json", waf); err != nil {
		return err
	}
	if err := e.Workspace.WriteJSON("06_web/openapi.json", openAPI); err != nil {
		return err
	}
	return e.Workspace.WriteJSON("06_web/screenshots.json", screenshots)
}

type jsAnalysisResult struct {
	URL              string   `json:"url"`
	Endpoints        []string `json:"endpoints,omitempty"`
	SecretIndicators []any    `json:"secret_indicators,omitempty"`
	Error            string   `json:"error,omitempty"`
}

type screenshotResult struct {
	URL   string `json:"url"`
	Path  string `json:"path,omitempty"`
	Error string `json:"error,omitempty"`
}

type openAPIResult struct {
	URL     string   `json:"url"`
	Version string   `json:"version,omitempty"`
	Paths   []string `json:"paths,omitempty"`
}

func (e *Engine) analyzeJavaScript(ctx context.Context, web []model.WebResult) []jsAnalysisResult {
	output := make([]jsAnalysisResult, 0)
	for _, result := range web {
		if len(output) >= 100 {
			e.State.AddWarning("JavaScript analysis capped at 100 responses")
			break
		}
		contentType := strings.ToLower(result.Headers["Content-Type"])
		if !strings.Contains(contentType, "javascript") && !strings.HasSuffix(strings.ToLower(strings.Split(result.FinalURL, "?")[0]), ".js") {
			continue
		}
		content, err := e.runPythonModule(ctx, "js_analysis", []string{"--url", result.FinalURL}, result.Body)
		entry := jsAnalysisResult{URL: result.FinalURL}
		if err != nil {
			entry.Error = err.Error()
			e.State.AddWarning("JS analysis " + result.FinalURL + ": " + err.Error())
		} else {
			var payload struct {
				Endpoints        []string `json:"endpoints"`
				SecretIndicators []any    `json:"secret_indicators"`
			}
			if parseErr := json.Unmarshal(content, &payload); parseErr != nil {
				entry.Error = parseErr.Error()
			} else {
				entry.Endpoints, entry.SecretIndicators = payload.Endpoints, payload.SecretIndicators
			}
		}
		output = append(output, entry)
	}
	return output
}

func (e *Engine) captureScreenshots(ctx context.Context, web []model.WebResult) []screenshotResult {
	if err := os.MkdirAll(e.Workspace.Path("06_web", "screenshots"), 0o750); err != nil {
		return []screenshotResult{{Error: err.Error()}}
	}
	output := make([]screenshotResult, 0)
	for _, result := range web {
		if len(output) >= 50 {
			e.State.AddWarning("screenshot capture capped at 50 URLs")
			break
		}
		if result.StatusCode < 200 || result.StatusCode >= 400 {
			continue
		}
		name := safeName(result.Host+"_"+strconv.Itoa(result.StatusCode)+"_"+strconv.Itoa(len(output))) + ".png"
		path := e.Workspace.Path("06_web", "screenshots", name)
		entry := screenshotResult{URL: result.FinalURL, Path: path}
		if _, err := e.runPythonModule(ctx, "screenshot", []string{"--url", result.FinalURL, "--out", path}, ""); err != nil {
			entry.Error = err.Error()
			e.State.AddWarning("screenshot " + result.FinalURL + ": " + err.Error())
		}
		output = append(output, entry)
	}
	return output
}

func detectWAF(web []model.WebResult) map[string][]string {
	output := make(map[string][]string)
	for _, result := range web {
		combined := strings.ToLower(result.Headers["Server"] + " " + result.Headers["X-Powered-By"] + " " + result.Body[:min(len(result.Body), 4096)])
		for marker, provider := range map[string]string{"cloudflare": "Cloudflare", "akamai": "Akamai", "imperva": "Imperva", "incapsula": "Imperva", "awswaf": "AWS WAF", "sucuri": "Sucuri", "mod_security": "ModSecurity"} {
			if strings.Contains(combined, marker) {
				output[result.FinalURL] = append(output[result.FinalURL], provider)
			}
		}
		output[result.FinalURL] = sortedUnique(output[result.FinalURL])
	}
	return output
}

func extractOpenAPI(web []model.WebResult) []openAPIResult {
	output := make([]openAPIResult, 0)
	for _, result := range web {
		var payload struct {
			OpenAPI string                     `json:"openapi"`
			Swagger string                     `json:"swagger"`
			Paths   map[string]json.RawMessage `json:"paths"`
		}
		if json.Unmarshal([]byte(result.Body), &payload) != nil || (payload.OpenAPI == "" && payload.Swagger == "") {
			continue
		}
		paths := make([]string, 0, len(payload.Paths))
		for path := range payload.Paths {
			paths = append(paths, path)
		}
		sort.Strings(paths)
		version := payload.OpenAPI
		if version == "" {
			version = payload.Swagger
		}
		output = append(output, openAPIResult{URL: result.FinalURL, Version: version, Paths: paths})
	}
	return output
}

func (e *Engine) runWAFW00F(ctx context.Context, web []model.WebResult) {
	for _, result := range web {
		if result.StatusCode == 0 {
			continue
		}
		path := "06_web/wafw00f_" + safeName(result.Host) + ".txt"
		if err := e.runTool(ctx, "wafw00f", []string{result.FinalURL}, path, ""); err != nil {
			e.State.AddWarning("wafw00f " + result.FinalURL + ": " + err.Error())
		}
	}
}

func (e *Engine) runTestSSL(ctx context.Context, web []model.WebResult) {
	for _, result := range web {
		if !strings.HasPrefix(result.FinalURL, "https://") {
			continue
		}
		path := "06_web/testssl_" + safeName(result.Host) + ".txt"
		if err := e.runTool(ctx, "testssl.sh", []string{"--quiet", result.FinalURL}, path, ""); err != nil {
			e.State.AddWarning("testssl " + result.FinalURL + ": " + err.Error())
		}
	}
}

func (e *Engine) phase7(ctx context.Context) error {
	_, _, _, web, _, _, _ := e.State.Snapshot()
	urls := make([]string, 0, len(web))
	for _, value := range web {
		if value.StatusCode > 0 {
			urls = append(urls, value.FinalURL)
		}
	}
	sort.Strings(urls)
	if len(urls) == 0 {
		e.State.AddWarning("no responsive web targets were available for optional web vulnerability checks")
	}
	if e.Config.Nuclei && len(urls) > 0 {
		path := "07_vulns/nuclei_findings.jsonl"
		if err := e.runTool(ctx, "nuclei", []string{"-l", e.Workspace.Path("06_web", "urls.txt"), "-jsonl", "-silent", "-severity", "critical,high,medium"}, path, strings.Join(urls, "\n")+"\n"); err != nil {
			e.State.AddWarning(err.Error())
		}
		if content, err := os.ReadFile(e.Workspace.Path(path)); err == nil && len(content) > 0 {
			findings, parseErr := external.ParseNucleiJSONL(strings.NewReader(string(content)))
			if parseErr != nil {
				e.State.AddWarning("parse nuclei output: " + parseErr.Error())
			} else {
				for _, finding := range findings {
					e.State.AddFinding(finding)
				}
			}
		}
	}
	if e.Config.Nikto && len(urls) > 0 {
		for _, value := range urls {
			path := "07_vulns/nikto_" + safeName(value) + ".json"
			if err := e.runTool(ctx, "nikto", []string{"-host", value, "-nointeractive", "-Format", "json"}, path, ""); err != nil {
				e.State.AddWarning(err.Error())
			}
			e.parseToolReportFile("nikto", path, value)
		}
	}
	if e.Config.SQLMap && len(urls) > 0 {
		for _, value := range urls {
			if strings.Contains(value, "?") {
				outputDir := e.Workspace.Path("07_vulns", "sqlmap", safeName(value))
				if err := os.MkdirAll(outputDir, 0o750); err != nil {
					return err
				}
				path := "07_vulns/sqlmap_" + safeName(value) + ".txt"
				if err := e.runTool(ctx, "sqlmap", []string{"-u", value, "--batch", "--level=2", "--risk=1", "--output-dir", outputDir}, path, ""); err != nil {
					e.State.AddWarning(err.Error())
				}
				e.parseToolReportFile("sqlmap", path, value)
			}
		}
	}
	if e.Config.WPScan && len(urls) > 0 {
		for _, value := range urls {
			path := "07_vulns/wpscan_" + safeName(value) + ".json"
			if err := e.runTool(ctx, "wpscan", []string{"--url", value, "--no-update", "--format", "json"}, path, ""); err != nil {
				e.State.AddWarning(err.Error())
			}
			e.parseToolReportFile("wpscan", path, value)
		}
	}
	if e.Config.ActiveChecks {
		e.runNativeVulnChecks(ctx, web)
	}
	cveFindings := make([]model.Finding, 0)
	if e.Config.NVD {
		if e.Config.CVEDB == "" {
			e.State.AddWarning("--nvd requires --cve-db pointing to a local NVD JSON feed")
		} else {
			services := make([]model.Service, 0)
			for _, host := range e.State.HostList() {
				services = append(services, host.Services...)
			}
			matches, matchErr := cve.MatchFile(e.Config.CVEDB, services)
			if matchErr != nil {
				e.State.AddWarning("NVD matching: " + matchErr.Error())
			} else {
				cveFindings = matches
				for _, finding := range matches {
					e.State.AddFinding(finding)
				}
			}
		}
	}
	_, _, _, _, allFindings, _, _ := e.State.Snapshot()
	toolFindings := make([]model.Finding, 0)
	for _, finding := range allFindings {
		if strings.HasPrefix(finding.Source, "phase7-") {
			toolFindings = append(toolFindings, finding)
		}
	}
	if err := e.Workspace.WriteJSON("07_vulns/tool_findings.json", toolFindings); err != nil {
		return err
	}
	if err := e.Workspace.WriteJSON("07_vulns/cve_matches.json", cveFindings); err != nil {
		return err
	}
	if err := e.Workspace.WriteJSON("07_vulns/custom_findings.json", []any{}); err != nil {
		return err
	}
	return e.Workspace.WriteText("07_vulns/README.txt", "External scanner raw output is retained in this directory. Tool-reported results are marked as unverified until manually validated.\n")
}

func (e *Engine) phase8(ctx context.Context) error {
	_, _, _, web, _, _, _ := e.State.Snapshot()
	found := make([]model.Finding, 0)
	exposed := make([]map[string]any, 0)
	for _, result := range web {
		content := result.Body
		for key, value := range result.Headers {
			content += "\n" + key + ": " + value
		}
		found = append(found, secrets.Findings(result.FinalURL, content, e.Config.ShowSecrets)...)
		if parsed, err := url.Parse(result.FinalURL); err == nil && result.StatusCode < 400 && secrets.LooksSensitivePath(parsed.Path) {
			exposed = append(exposed, map[string]any{"url": result.FinalURL, "status_code": result.StatusCode, "path": parsed.Path})
		}
	}
	for _, finding := range found {
		e.State.AddFinding(finding)
	}
	entities := map[string]any{}
	if e.Config.NLP {
		text := strings.Builder{}
		for _, result := range web {
			if text.Len() >= 2_000_000 {
				break
			}
			remaining := 2_000_000 - text.Len()
			body := result.Body
			if len(body) > remaining {
				body = body[:remaining]
			}
			text.WriteString(body)
			text.WriteByte('\n')
		}
		if output, err := e.runPythonModule(ctx, "nlp", nil, text.String()); err != nil {
			e.State.AddWarning("NLP extraction: " + err.Error())
		} else if err := json.Unmarshal(output, &entities); err != nil {
			e.State.AddWarning("parse NLP output: " + err.Error())
		}
	}
	if err := e.Workspace.WriteJSON("08_secrets/secrets.json", found); err != nil {
		return err
	}
	if err := e.Workspace.WriteJSON("08_secrets/entities.json", entities); err != nil {
		return err
	}
	return e.Workspace.WriteJSON("08_secrets/exposed_files.json", exposed)
}

func (e *Engine) phase9() error {
	_, _, _, _, findings, _, _ := e.State.Snapshot()
	findings = scoring.Normalize(scoring.AnnotateContext(findings))
	e.State.ReplaceFindings(findings)
	e.risk = scoring.Score(findings)
	if err := e.Workspace.WriteJSON("09_report/risk_scores.json", e.risk); err != nil {
		return err
	}
	return e.Workspace.WriteJSON("09_report/prioritized_findings.json", findings)
}

func (e *Engine) phase10() error {
	return e.writeReports(e.buildReport())
}

func (e *Engine) writeReports(value model.Report) error {
	if err := report.JSON(e.Workspace.Path("09_report", "report.json"), value); err != nil {
		return err
	}
	if err := report.CSV(e.Workspace.Path("09_report", "findings.csv"), value.Findings); err != nil {
		return err
	}
	if err := report.HTML(e.Workspace.Path("09_report", "report.html"), value); err != nil {
		return err
	}
	if e.Config.JSON != "" {
		if err := report.JSON(e.Config.JSON, value); err != nil {
			return err
		}
	}
	if e.Config.CSV != "" {
		if err := report.CSV(e.Config.CSV, value.Findings); err != nil {
			return err
		}
	}
	if e.Config.HTML != "" {
		if err := report.HTML(e.Config.HTML, value); err != nil {
			return err
		}
	}
	if e.Config.PDF != "" {
		html := e.Config.HTML
		if html == "" {
			html = e.Workspace.Path("09_report", "report.html")
		}
		if err := report.PDF(e.Config.PDF, html); err != nil {
			e.State.AddWarning(err.Error())
		}
	}
	if e.Config.Diff != "" {
		previous, err := report.Load(e.Config.Diff)
		if err != nil {
			return fmt.Errorf("load diff workspace: %w", err)
		}
		if err = e.Workspace.WriteJSON("09_report/diff.json", report.Diff(previous, value)); err != nil {
			return err
		}
	}
	return nil
}

func (e *Engine) buildReport() model.Report {
	target, hosts, records, web, findings, warnings, phases := e.State.Snapshot()
	risk := e.risk
	if risk.BySeverity == nil {
		risk = scoring.Score(findings)
	}
	return model.Report{SchemaVersion: model.SchemaVersion, GeneratedAt: time.Now().UTC(), Target: target, Hosts: hosts, DNS: records, Web: web, Findings: findings, Risk: risk, Phases: phases, Warnings: warnings, Stats: e.stats, Screenshots: e.screenshots}
}

const defaultSecListsSubdomainWordlist = "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt"

var permutationAffixes = []string{"dev", "staging", "test", "old", "new", "api", "app", "admin", "portal"}

// subdomainPermutations applies the plan's numeric and environment mutations
// to a bounded, deterministic seed set. Variants use only valid DNS labels.
func subdomainPermutations(words []string, maximum int) []string {
	if maximum < 1 {
		return nil
	}
	output := make([]string, 0, maximum)
	seen := make(map[string]struct{}, maximum)
	add := func(candidate string) bool {
		candidate = strings.ToLower(strings.TrimSpace(candidate))
		if candidate == "" || len(candidate) > 63 || strings.HasPrefix(candidate, "-") || strings.HasSuffix(candidate, "-") {
			return false
		}
		for _, character := range candidate {
			if character != '-' && (character < 'a' || character > 'z') && (character < '0' || character > '9') {
				return false
			}
		}
		if _, exists := seen[candidate]; exists {
			return false
		}
		seen[candidate] = struct{}{}
		output = append(output, candidate)
		return len(output) >= maximum
	}
	for _, word := range sortedUnique(words) {
		for _, affix := range permutationAffixes {
			if add(affix+"-"+word) || add(word+"-"+affix) {
				return sortedUnique(output)
			}
		}
		for number := 0; number < 100; number++ {
			value := strconv.Itoa(number)
			if add(word+value) || add(word+"-"+value) || add(value+"-"+word) {
				return sortedUnique(output)
			}
		}
	}
	return sortedUnique(output)
}

func subdomainLabels(root string, names []string) []string {
	root = strings.TrimSuffix(strings.ToLower(root), ".")
	labels := make([]string, 0)
	for _, name := range names {
		name = strings.TrimSuffix(strings.ToLower(name), ".")
		if name == root || !strings.HasSuffix(name, "."+root) {
			continue
		}
		prefix := strings.TrimSuffix(name, "."+root)
		labels = append(labels, strings.Split(prefix, ".")...)
	}
	return sortedUnique(labels)
}

func (e *Engine) subdomainPermutationLimit() int {
	limit := e.Config.SubdomainMaxPermutations
	if e.Config.Fast && limit > 1000 {
		limit = 1000
	}
	return limit
}

// subdomainWords merges the installed SecLists 5000-word source with an
// optional user wordlist. Each source has the configured cap, so a custom list
// supplements rather than replaces the standard source. If SecLists is not
// installed, the embedded list retains portable-binary behavior.
func (e *Engine) subdomainWords() ([]string, error) {
	maximum := e.Config.SubdomainMaxWords
	if e.Config.Fast && maximum > 1000 {
		maximum = 1000
	}
	paths := make([]string, 0, 2)
	custom := strings.TrimSpace(e.Config.SubdomainWordlist)
	if custom != "" {
		paths = append(paths, custom)
	}
	if info, err := os.Stat(defaultSecListsSubdomainWordlist); err == nil && !info.IsDir() && defaultSecListsSubdomainWordlist != custom {
		paths = append(paths, defaultSecListsSubdomainWordlist)
	}
	words, failures := mergeSubdomainWordSources(paths, maximum)
	if err, unavailable := failures[custom]; unavailable && e.State != nil {
		e.State.AddWarning("custom subdomain wordlist unavailable: " + err.Error())
	}
	if len(words) > 0 {
		return words, nil
	}
	words = assets.SubdomainWords()
	if len(words) > maximum {
		words = words[:maximum]
	}
	return words, nil
}

func mergeSubdomainWordSources(paths []string, maximum int) ([]string, map[string]error) {
	words := make([]string, 0, maximum*max(1, len(paths)))
	failures := make(map[string]error)
	seen := make(map[string]struct{})
	for _, path := range paths {
		if path == "" {
			continue
		}
		loaded, err := dns.LoadWords(path, maximum)
		if err != nil {
			failures[path] = err
			continue
		}
		for _, word := range loaded {
			if _, exists := seen[word]; exists {
				continue
			}
			seen[word] = struct{}{}
			words = append(words, word)
		}
	}
	return words, failures
}

func (e *Engine) directoryWords() ([]string, error) {
	var content []byte
	if e.Config.DirectoryWordlist == "" {
		content = []byte(strings.Join(assets.DirectoryWords(), "\n"))
	} else {
		var err error
		content, err = os.ReadFile(e.Config.DirectoryWordlist)
		if err != nil {
			return nil, err
		}
	}
	maximum := 500
	if e.Config.Fast {
		maximum = 100
	}
	if e.Config.Deep {
		maximum = 5000
	}
	seen, words := map[string]struct{}{}, make([]string, 0)
	for _, line := range strings.Split(string(content), "\n") {
		word := strings.Trim(strings.TrimSpace(strings.SplitN(line, "#", 2)[0]), "/")
		if word == "" || strings.Contains(word, "..") {
			continue
		}
		if _, found := seen[word]; found {
			continue
		}
		seen[word] = struct{}{}
		words = append(words, word)
		if len(words) >= maximum {
			break
		}
	}
	return words, nil
}

func (e *Engine) discoverAPI(ctx context.Context, client *httpx.Client, seeds []model.WebResult) {
	paths := []string{"/api", "/api/v1", "/graphql", "/swagger", "/swagger/index.html", "/openapi.json", "/docs", "/redoc"}
	targets := make(map[string]struct{})
	for _, seed := range seeds {
		if seed.Error != "" || seed.StatusCode == 0 {
			continue
		}
		parsed, err := url.Parse(seed.FinalURL)
		if err != nil {
			continue
		}
		parsed.RawQuery, parsed.Fragment = "", ""
		for _, path := range paths {
			candidate := *parsed
			candidate.Path = path
			targets[candidate.String()] = struct{}{}
		}
	}
	urls := make([]string, 0, len(targets))
	for target := range targets {
		urls = append(urls, target)
	}
	sort.Strings(urls)
	for _, result := range parallelProbe(ctx, client, urls, min(e.Config.Workers, 25)) {
		if result.Error != "" || result.StatusCode >= 400 {
			continue
		}
		e.State.AddWeb(result)
		e.addWebFindings(result)
	}
}

func (e *Engine) checkCloudAssets(ctx context.Context, names []string) []cloud.Result {
	candidates := cloud.Candidates(names, e.Config.CloudAssetMaxCandidates)
	if len(candidates) == 0 {
		return []cloud.Result{}
	}
	urls := make([]string, len(candidates))
	for index, candidate := range candidates {
		urls[index] = candidate.URL
	}
	client := httpx.New(e.Config.Timeout, e.Config.UserAgent)
	probes := parallelProbeHeadRateLimited(ctx, client, urls, min(e.Config.Workers, 25), e.Config.Rate)
	byURL := make(map[string]model.WebResult, len(probes))
	fallbackURLs := make([]string, 0)
	for _, probe := range probes {
		byURL[probe.URL] = probe
		if cloud.NeedsGETFallback(probe.StatusCode, probe.Error) {
			fallbackURLs = append(fallbackURLs, probe.URL)
		}
	}
	// Some object stores reject HEAD even though an equivalent root GET is
	// accepted. The fallback stays body-limited by httpx and only happens for
	// an explicit method rejection, never for normal access-denied responses.
	for _, probe := range parallelProbeRateLimited(ctx, client, fallbackURLs, min(e.Config.Workers, 25), e.Config.Rate) {
		byURL[probe.URL] = probe
	}
	results := make([]cloud.Result, 0, len(candidates))
	for _, candidate := range candidates {
		probe, found := byURL[candidate.URL]
		if !found {
			results = append(results, cloud.Classify(candidate, 0, "probe did not complete"))
			continue
		}
		results = append(results, cloud.Classify(candidate, probe.StatusCode, probe.Error))
	}
	sort.Slice(results, func(i, j int) bool { return results[i].URL < results[j].URL })
	return results
}

func (e *Engine) contentDiscovery(ctx context.Context, client *httpx.Client, seeds []model.WebResult) {
	words, err := e.directoryWords()
	if err != nil {
		e.State.AddWarning("content discovery wordlist: " + err.Error())
		return
	}
	targets := map[string]struct{}{}
	for _, seed := range seeds {
		if seed.Error != "" || seed.StatusCode == 0 {
			continue
		}
		parsed, parseErr := url.Parse(seed.FinalURL)
		if parseErr != nil {
			continue
		}
		parsed.Path, parsed.RawQuery, parsed.Fragment = "/", "", ""
		for _, word := range words {
			candidate := *parsed
			candidate.Path = "/" + word
			targets[candidate.String()] = struct{}{}
		}
	}
	urls := make([]string, 0, len(targets))
	for target := range targets {
		urls = append(urls, target)
	}
	sort.Strings(urls)
	for _, result := range parallelProbe(ctx, client, urls, e.Config.Workers) {
		if result.Error != "" || result.StatusCode >= 400 {
			continue
		}
		e.State.AddWeb(result)
		e.addWebFindings(result)
		if parsed, parseErr := url.Parse(result.FinalURL); parseErr == nil && secrets.LooksSensitivePath(parsed.Path) {
			severity := model.SeverityHigh
			path := strings.ToLower(parsed.Path)
			if strings.Contains(path, ".env") || strings.Contains(path, "id_rsa") || strings.Contains(path, ".pem") || strings.Contains(path, ".key") {
				severity = model.SeverityCritical
			}
			e.State.AddFinding(model.Finding{Severity: severity, Title: "Potentially sensitive file is web-accessible", Description: "A content-discovery probe received a successful response for a path associated with configuration, source-control, backup, or key material.", Asset: result.Host, URL: result.FinalURL, Evidence: fmt.Sprintf("HTTP %d for %s", result.StatusCode, parsed.Path), MITRE: []string{"T1552.001"}, Remediation: "Remove the file from the web root, restrict access, and rotate any data it may contain.", Confidence: "medium", Source: "phase6-content-discovery"})
		}
	}
}

type takeoverCandidate struct {
	Host       string `json:"host"`
	CNAME      string `json:"cname"`
	Provider   string `json:"provider"`
	Confidence string `json:"confidence"`
	Status     string `json:"status"`
	Evidence   string `json:"evidence,omitempty"`
}

// detectPotentialTakeovers is deliberately conservative. A provider CNAME is
// evidence worth reviewing, but it is not proof that an account is unclaimed.
// By default every discovered CNAME is checked; a positive operator cap can
// deliberately narrow the work, while Phase 2's global probe budget remains
// the hard safety bound.
func (e *Engine) detectPotentialTakeovers(ctx context.Context, names []string) []takeoverCandidate {
	if e.Config.TakeoverMaxChecks > 0 && len(names) > e.Config.TakeoverMaxChecks {
		e.State.AddWarning(fmt.Sprintf("takeover CNAME checks capped at %d names", e.Config.TakeoverMaxChecks))
		names = names[:e.Config.TakeoverMaxChecks]
	}
	aliases := dns.CNAMEManyRateLimited(ctx, names, min(e.Config.Workers, 100), e.Config.Rate)
	output := make([]takeoverCandidate, 0, len(aliases))
	for host, alias := range aliases {
		provider := takeoverProvider(alias)
		if provider == "" {
			continue
		}
		output = append(output, takeoverCandidate{Host: host, CNAME: alias, Provider: provider, Confidence: "low", Status: "candidate_requires_manual_validation"})
	}
	sort.Slice(output, func(i, j int) bool { return output[i].Host < output[j].Host })
	return output
}

func (e *Engine) verifyTakeovers(ctx context.Context, candidates []takeoverCandidate) []takeoverCandidate {
	if len(candidates) == 0 {
		return candidates
	}
	client := httpx.New(e.Config.Timeout, e.Config.UserAgent)
	httpsTargets := make([]string, len(candidates))
	httpsIndex := make(map[string]int, len(candidates))
	for index, candidate := range candidates {
		target := "https://" + candidate.Host + "/"
		httpsTargets[index], httpsIndex[target] = target, index
	}
	probes := make([]model.WebResult, len(candidates))
	completed := make([]bool, len(candidates))
	fallbackTargets := make([]string, 0)
	httpIndex := make(map[string]int)
	for _, probe := range parallelProbeRateLimited(ctx, client, httpsTargets, min(e.Config.Workers, 25), e.Config.Rate) {
		index, found := httpsIndex[probe.URL]
		if !found {
			continue
		}
		probes[index], completed[index] = probe, true
		if probe.Error != "" {
			target := "http://" + candidates[index].Host + "/"
			fallbackTargets, httpIndex[target] = append(fallbackTargets, target), index
		}
	}
	for _, probe := range parallelProbeRateLimited(ctx, client, fallbackTargets, min(e.Config.Workers, 25), e.Config.Rate) {
		if index, found := httpIndex[probe.URL]; found {
			probes[index], completed[index] = probe, true
		}
	}
	for index := range candidates {
		candidate := &candidates[index]
		probe := probes[index]
		if !completed[index] || probe.Error != "" {
			candidate.Status, candidate.Evidence = "verification_inconclusive", firstNonEmptyString(probe.Error, "probe did not complete")
			continue
		}
		marker := unclaimedMarker(candidate.Provider, probe.Body)
		if marker != "" {
			candidate.Status, candidate.Confidence, candidate.Evidence = "potentially_unclaimed", "medium", marker
			e.State.AddFinding(model.Finding{Severity: model.SeverityHigh, Title: "Potential subdomain takeover", Description: "A known third-party CNAME target returned an unclaimed-resource signature. Validate ownership before remediation or disclosure.", Asset: candidate.Host, URL: probe.FinalURL, Evidence: marker, MITRE: []string{"T1584.001"}, Remediation: "Remove the stale DNS record or claim and correctly configure the referenced third-party resource.", Confidence: "medium", Source: "phase2-takeover"})
		} else {
			candidate.Status, candidate.Evidence = "no_known_unclaimed_signature", fmt.Sprintf("HTTP %d", probe.StatusCode)
		}
	}
	return candidates
}

type takeoverSignature struct {
	Provider string
	Suffixes []string
	Markers  []string
}

var takeoverSignatures = []takeoverSignature{
	{Provider: "Heroku", Suffixes: []string{"herokudns.com", "herokuapp.com"}, Markers: []string{"no such app", "there's nothing here"}},
	{Provider: "Ghost", Suffixes: []string{"ghost.io", "ghost.org"}, Markers: []string{"the thing you were looking for is no longer here", "site not found"}},
	{Provider: "Fastly", Suffixes: []string{"fastly.net", "fastlylb.net"}, Markers: []string{"fastly error: unknown domain", "unknown domain"}},
	{Provider: "Shopify", Suffixes: []string{"myshopify.com", "shops.myshopify.com"}, Markers: []string{"sorry, this shop is currently unavailable"}},
	{Provider: "GitHub Pages", Suffixes: []string{"github.io"}, Markers: []string{"there isn't a github pages site here"}},
	{Provider: "Azure App Service", Suffixes: []string{"azurewebsites.net", "cloudapp.azure.com"}, Markers: []string{"error 404 - web app not found", "web app not found"}},
	{Provider: "Azure Traffic Manager", Suffixes: []string{"trafficmanager.net"}, Markers: []string{"profile not found", "traffic manager profile"}},
	{Provider: "Amazon S3 website", Suffixes: []string{"s3.amazonaws.com", "s3-website-us-east-1.amazonaws.com", "s3-website-us-west-2.amazonaws.com"}, Markers: []string{"nosuchbucket", "the specified bucket does not exist"}},
	{Provider: "Netlify", Suffixes: []string{"netlify.app", "netlify.com"}, Markers: []string{"not found - request id", "site not found"}},
	{Provider: "Bitbucket", Suffixes: []string{"bitbucket.io"}, Markers: []string{"repository not found", "the requested repository either does not exist"}},
	{Provider: "Travis CI", Suffixes: []string{"travis-ci.com", "travis-ci.org"}, Markers: []string{"repository not known to travis ci", "could not find the repository"}},
}

func unclaimedMarker(provider, body string) string {
	lower := strings.ToLower(body)
	for _, signature := range takeoverSignatures {
		if signature.Provider != provider {
			continue
		}
		for _, marker := range signature.Markers {
			if strings.Contains(lower, marker) {
				return marker
			}
		}
	}
	return ""
}

func takeoverProvider(cname string) string {
	value := strings.TrimSuffix(strings.ToLower(cname), ".")
	// S3 names include regional and website endpoint variants, so enumerate
	// their documented shape without incorrectly treating every AWS hostname
	// as a bucket candidate.
	if strings.HasSuffix(value, ".amazonaws.com") && (strings.Contains(value, ".s3.") || strings.Contains(value, ".s3-website.") || strings.Contains(value, ".s3-website-")) {
		return "Amazon S3 website"
	}
	for _, signature := range takeoverSignatures {
		for _, suffix := range signature.Suffixes {
			if value == suffix || strings.HasSuffix(value, "."+suffix) {
				return signature.Provider
			}
		}
	}
	return ""
}

func (e *Engine) previousSubdomains() (map[string]struct{}, error) {
	output := make(map[string]struct{})
	if e.Config.Diff == "" {
		return output, nil
	}
	path := e.Config.Diff
	info, err := os.Stat(path)
	if err != nil {
		return output, err
	}
	if info.IsDir() {
		path = filepath.Join(path, "02_subdomains", "all_subdomains.txt")
	} else {
		return output, nil
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return output, err
	}
	for _, value := range strings.Fields(string(content)) {
		output[strings.ToLower(strings.TrimSuffix(value, "."))] = struct{}{}
	}
	return output, nil
}

func (e *Engine) writeEmptySubdomains() error {
	if err := e.Workspace.WriteText("02_subdomains/all_subdomains.txt", ""); err != nil {
		return err
	}
	if err := e.Workspace.WriteText("02_subdomains/all_ips.txt", ""); err != nil {
		return err
	}
	if err := e.Workspace.WriteText("02_subdomains/new_subdomains.txt", ""); err != nil {
		return err
	}
	if err := e.Workspace.WriteJSON("02_subdomains/subdomain_ips.json", map[string][]string{}); err != nil {
		return err
	}
	if err := e.Workspace.WriteJSON("02_subdomains/cloud_assets.json", []any{}); err != nil {
		return err
	}
	return e.Workspace.WriteJSON("02_subdomains/takeovers.json", []any{})
}
func (e *Engine) scanOptions() scanner.Options {
	return scanner.Options{Workers: e.Config.Workers, Rate: e.Config.Rate, Timeout: e.Config.Timeout, Retries: e.Config.Retries}
}
func (e *Engine) checkProbeBudget(hosts, ports int) error {
	if hosts > 0 && ports > 0 && hosts > e.Config.MaxProbes/ports && !e.Config.UnsafeLargeScan {
		return fmt.Errorf("scan requires more than max-probes=%d; reduce scope or pass --unsafe-large-scan", e.Config.MaxProbes)
	}
	return nil
}

func (e *Engine) icmpSweep(ctx context.Context, addresses []netip.Addr) []netip.Addr {
	binary, err := exec.LookPath("ping")
	if err != nil {
		e.State.AddWarning("ICMP discovery requested but ping is not installed")
		return nil
	}
	jobs := make(chan netip.Addr)
	results := make(chan netip.Addr, min(e.Config.Workers, 50))
	var group sync.WaitGroup
	for worker := 0; worker < min(e.Config.Workers, 50); worker++ {
		group.Add(1)
		go func() {
			defer group.Done()
			for address := range jobs {
				probeCtx, cancel := context.WithTimeout(ctx, e.Config.Timeout)
				err := exec.CommandContext(probeCtx, binary, "-c", "1", "-W", "1", address.String()).Run()
				cancel()
				if err == nil {
					select {
					case results <- address:
					case <-ctx.Done():
						return
					}
				}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, address := range addresses {
			select {
			case jobs <- address:
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() { group.Wait(); close(results) }()
	output := make([]netip.Addr, 0)
	for address := range results {
		output = append(output, address)
	}
	sort.Slice(output, func(i, j int) bool { return output[i].Compare(output[j]) < 0 })
	return output
}

func (e *Engine) masscanPreScan(ctx context.Context) ([]scanner.Result, error) {
	binary, err := e.lookupTool("masscan")
	if err != nil {
		return nil, fmt.Errorf("masscan is not installed")
	}
	if e.parsed.Profile.CIDR == "" {
		return nil, fmt.Errorf("masscan pre-scan requires a CIDR target")
	}
	outputPath := e.Workspace.Path("04_ports", "masscan.list")
	arguments := []string{"-p1-65535", "--rate", strconv.Itoa(max(1, e.Config.Rate*10)), "--wait", "0", "--open-only", "-oL", outputPath, e.parsed.Profile.CIDR}
	command := exec.CommandContext(ctx, binary, arguments...)
	commandOutput, commandErr := command.CombinedOutput()
	if err := e.Workspace.WriteBytes("04_ports/masscan.log", commandOutput); err != nil {
		return nil, err
	}
	if commandErr != nil {
		return nil, fmt.Errorf("masscan: %w", commandErr)
	}
	content, err := os.Open(outputPath)
	if err != nil {
		return nil, err
	}
	defer content.Close()
	return external.ParseMasscanList(content)
}

func (e *Engine) enumerateServices(ctx context.Context) {
	_, hosts, _, _, _, _, _ := e.State.Snapshot()
	jobs := make(chan struct {
		host string
		port int
	})
	var group sync.WaitGroup
	for i := 0; i < min(e.Config.Workers, 100); i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			for job := range jobs {
				service := scanner.ProbeService(ctx, job.host, job.port, e.Config.Timeout, e.serverName(job.host))
				if e.Config.ServiceDetails {
					service = services.Enrich(ctx, service, e.Config.Timeout)
				}
				e.State.AddService(service)
			}
		}()
	}
	for _, host := range hosts {
		for _, port := range host.OpenTCP {
			e.stats.Probes++
			select {
			case jobs <- struct {
				host string
				port int
			}{host.IP, port}:
			case <-ctx.Done():
				close(jobs)
				group.Wait()
				return
			}
		}
	}
	close(jobs)
	group.Wait()
}
func (e *Engine) serverName(host string) string {
	profile, _, _, _, _, _, _ := e.State.Snapshot()
	if profile.Hostname != "" && contains(profile.IPs, host) {
		return profile.Hostname
	}
	return ""
}

func (e *Engine) webTargets(profile model.TargetProfile, hosts []model.Host) []string {
	set := map[string]struct{}{}
	if profile.URL != "" {
		set[profile.URL] = struct{}{}
	}
	for _, host := range hosts {
		for _, service := range host.Services {
			if service.Name != "http" && service.Name != "https" && service.Port != 80 && service.Port != 443 && service.Port != 8080 && service.Port != 8443 {
				continue
			}
			scheme := "http"
			if service.Name == "https" || service.Port == 443 || service.Port == 8443 {
				scheme = "https"
			}
			name := host.IP
			if profile.Hostname != "" && contains(profile.IPs, host.IP) {
				name = profile.Hostname
			}
			parsed := url.URL{Scheme: scheme, Host: net.JoinHostPort(name, strconv.Itoa(service.Port))}
			if (scheme == "http" && service.Port == 80) || (scheme == "https" && service.Port == 443) {
				parsed.Host = name
			}
			set[parsed.String()] = struct{}{}
		}
	}
	output := make([]string, 0, len(set))
	for value := range set {
		output = append(output, value)
	}
	sort.Strings(output)
	return output
}
func (e *Engine) addWebFindings(result model.WebResult) {
	if result.StatusCode == 0 {
		return
	}
	add := func(severity model.Severity, title, description, evidence, remediation string) {
		e.State.AddFinding(model.Finding{Severity: severity, Title: title, Description: description, Asset: result.Host, URL: result.FinalURL, Evidence: evidence, MITRE: []string{"T1189"}, Remediation: remediation, Confidence: "high", Source: "phase6-web"})
	}
	html := strings.Contains(strings.ToLower(result.Headers["Content-Type"]), "text/html")
	if strings.HasPrefix(result.FinalURL, "https://") && result.Headers["Strict-Transport-Security"] == "" {
		add(model.SeverityMedium, "Missing HTTP Strict Transport Security", "The HTTPS response did not include a Strict-Transport-Security header.", "Strict-Transport-Security header absent", "Set a suitable Strict-Transport-Security policy after validating HTTPS coverage.")
	}
	if result.Headers["X-Content-Type-Options"] == "" {
		add(model.SeverityLow, "Missing X-Content-Type-Options header", "The response did not declare nosniff protection.", "X-Content-Type-Options header absent", "Set X-Content-Type-Options: nosniff.")
	}
	if html && result.Headers["Content-Security-Policy"] == "" {
		add(model.SeverityLow, "Missing Content Security Policy", "The HTML response did not include a Content-Security-Policy header.", "Content-Security-Policy header absent", "Deploy a restrictive Content-Security-Policy appropriate for the application.")
	}
	if html && result.Headers["X-Frame-Options"] == "" && !strings.Contains(strings.ToLower(result.Headers["Content-Security-Policy"]), "frame-ancestors") {
		add(model.SeverityMedium, "Potential clickjacking protection missing", "Neither X-Frame-Options nor a CSP frame-ancestors directive was observed.", "X-Frame-Options and CSP frame-ancestors absent", "Set X-Frame-Options or a restrictive CSP frame-ancestors directive.")
	}
	if result.Headers["Referrer-Policy"] == "" {
		add(model.SeverityLow, "Missing Referrer-Policy header", "The response does not set a referrer disclosure policy.", "Referrer-Policy header absent", "Set a Referrer-Policy such as strict-origin-when-cross-origin.")
	}
	if result.Headers["Permissions-Policy"] == "" {
		add(model.SeverityLow, "Missing Permissions-Policy header", "The response does not explicitly constrain powerful browser features.", "Permissions-Policy header absent", "Set a Permissions-Policy appropriate to the application.")
	}
	if result.Headers["Access-Control-Allow-Origin"] == "*" && strings.EqualFold(result.Headers["Access-Control-Allow-Credentials"], "true") {
		add(model.SeverityMedium, "Potentially unsafe CORS policy", "The response combines wildcard cross-origin access with credential support; browsers generally reject this combination, but it should be reviewed.", "Access-Control-Allow-Origin: *; Access-Control-Allow-Credentials: true", "Use an allowlist of trusted origins and verify CORS behavior in browsers.")
	}
	for _, cookie := range result.Cookies {
		if strings.HasPrefix(result.FinalURL, "https://") && !cookie.Secure {
			add(model.SeverityMedium, "Cookie missing Secure attribute", "A cookie set by an HTTPS response can be sent over an insecure connection.", "Cookie: "+cookie.Name, "Set the Secure attribute on session and sensitive cookies.")
		}
		if !cookie.HTTPOnly {
			add(model.SeverityLow, "Cookie missing HttpOnly attribute", "A cookie is available to client-side scripts.", "Cookie: "+cookie.Name, "Set HttpOnly on cookies that do not need JavaScript access.")
		}
		if cookie.SameSite == "" {
			add(model.SeverityLow, "Cookie missing SameSite attribute", "A cookie does not declare cross-site request handling.", "Cookie: "+cookie.Name, "Set SameSite=Lax or SameSite=Strict unless a cross-site flow requires None; Secure.")
		}
	}
	if result.TLS != nil && result.TLS.NotAfter != "" {
		if expiry, err := time.Parse(time.RFC3339, result.TLS.NotAfter); err == nil {
			if expiry.Before(time.Now().UTC()) {
				add(model.SeverityHigh, "Expired TLS certificate", "The presented TLS leaf certificate has expired.", "Certificate expiry: "+result.TLS.NotAfter, "Replace the certificate and validate certificate automation monitoring.")
			} else if expiry.Before(time.Now().UTC().Add(30 * 24 * time.Hour)) {
				add(model.SeverityMedium, "TLS certificate expires soon", "The presented TLS leaf certificate expires within 30 days.", "Certificate expiry: "+result.TLS.NotAfter, "Renew the certificate before expiry and validate certificate automation monitoring.")
			}
		}
	}
}

func (e *Engine) lookupTool(tool string) (string, error) {
	configured := map[string]string{
		"nmap": e.Config.NmapPath, "masscan": e.Config.MasscanPath, "nuclei": e.Config.NucleiPath, "nikto": e.Config.NiktoPath,
		"sqlmap": e.Config.SQLMapPath, "wpscan": e.Config.WPScanPath, "testssl.sh": e.Config.TestSSLPath,
		"enum4linux": e.Config.Enum4LinuxPath, "snmpwalk": e.Config.SNMPWalkPath, "ldapsearch": e.Config.LDAPSearchPath, "smbclient": e.Config.SMBClientPath, "sherlock": e.Config.SherlockPath,
	}[tool]
	if configured != "" {
		info, err := os.Stat(configured)
		if err != nil || info.IsDir() {
			return "", fmt.Errorf("configured %s binary %q is unavailable", tool, configured)
		}
		return configured, nil
	}
	return exec.LookPath(tool)
}

func (e *Engine) runTool(ctx context.Context, tool string, arguments []string, destination, stdin string) error {
	binary, err := e.lookupTool(tool)
	if err != nil {
		return fmt.Errorf("%s requested but not installed", tool)
	}
	if tool == "nuclei" {
		if err := e.Workspace.WriteText("06_web/urls.txt", stdin); err != nil {
			return err
		}
	}
	e.stats.ToolInvocations++
	command := exec.CommandContext(ctx, binary, arguments...)
	output, commandErr := command.CombinedOutput()
	if writeErr := e.Workspace.WriteBytes(destination, output); writeErr != nil {
		return writeErr
	}
	if commandErr != nil {
		return fmt.Errorf("%s: %w", tool, commandErr)
	}
	return nil
}

func (e *Engine) runPythonModule(ctx context.Context, module string, arguments []string, input string) ([]byte, error) {
	python, err := exec.LookPath("python3")
	if err != nil {
		return nil, err
	}
	directory, err := filepath.Abs(e.Config.PythonDir)
	if err != nil {
		return nil, err
	}
	if info, statErr := os.Stat(directory); statErr != nil || !info.IsDir() {
		return nil, fmt.Errorf("python module directory %q not found", directory)
	}
	command := exec.CommandContext(ctx, python, append([]string{"-m", module}, arguments...)...)
	command.Env = append(os.Environ(), "PYTHONPATH="+directory)
	command.Stdin = strings.NewReader(input)
	output, err := command.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("python %s: %w: %s", module, err, strings.TrimSpace(string(output)))
	}
	return output, nil
}

func (e *Engine) pythonOSINT(ctx context.Context, profile model.TargetProfile) (osintOutput, error) {
	target := profile.Hostname
	if target == "" && len(profile.IPs) > 0 {
		target = profile.IPs[0]
	}
	if target == "" {
		return osintOutput{}, nil
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		return osintOutput{}, err
	}
	directory, err := filepath.Abs(e.Config.PythonDir)
	if err != nil {
		return osintOutput{}, err
	}
	if info, statErr := os.Stat(directory); statErr != nil || !info.IsDir() {
		return osintOutput{}, fmt.Errorf("python module directory %q not found", directory)
	}
	screenshotDir := e.Workspace.Path("01_osint", "screenshots")
	if err := os.MkdirAll(screenshotDir, 0o750); err != nil {
		return osintOutput{}, err
	}
	arguments := []string{"-m", "osint", "--target", target, "--screenshot-dir", screenshotDir}
	for _, address := range profile.IPs {
		arguments = append(arguments, "--ip", address)
	}
	if e.Config.OSINTAXFR {
		arguments = append(arguments, "--axfr")
	}
	if e.Config.SocialEnum {
		arguments = append(arguments, "--social-enum")
	}
	command := exec.CommandContext(ctx, python, arguments...)
	command.Env = append(os.Environ(), "PYTHONPATH="+directory)
	for key, value := range map[string]string{
		"RECONX_SHODAN_KEY":         e.Config.ShodanKey,
		"RECONX_CENSYS_KEY":         e.Config.CensysKey,
		"RECONX_CENSYS_ID":          e.Config.CensysID,
		"RECONX_CENSYS_SECRET":      e.Config.CensysSecret,
		"RECONX_VT_KEY":             e.Config.VTKey,
		"RECONX_URLSCAN_KEY":        e.Config.URLScanKey,
		"RECONX_GITHUB_TOKEN":       e.Config.GitHubToken,
		"RECONX_GITLAB_TOKEN":       e.Config.GitLabToken,
		"RECONX_SERP_KEY":           e.Config.SerpKey,
		"RECONX_HIBP_KEY":           e.Config.HIBPKey,
		"RECONX_SECURITYTRAILS_KEY": e.Config.SecurityTrailsKey,
		"RECONX_VIEWDNS_KEY":        e.Config.ViewDNSKey,
		"RECONX_IPINFO_TOKEN":       e.Config.IPInfoToken,
		"RECONX_SHERLOCK_PATH":      e.Config.SherlockPath,
		"RECONX_USER_AGENT":         e.Config.UserAgent,
	} {
		if value != "" {
			command.Env = append(command.Env, key+"="+value)
		}
	}
	output, err := command.Output()
	if err != nil {
		return osintOutput{}, err
	}
	var result osintOutput
	if err = json.Unmarshal(output, &result); err != nil {
		return osintOutput{}, fmt.Errorf("parse python output: %w", err)
	}
	return result, nil
}

type osintSecretIndicator struct {
	Source     string `json:"source"`
	Repository string `json:"repository,omitempty"`
	Path       string `json:"path,omitempty"`
	Indicator  string `json:"indicator"`
}

type osintEmployee struct {
	Name     string `json:"name"`
	Headline string `json:"headline,omitempty"`
	URL      string `json:"url,omitempty"`
	Source   string `json:"source,omitempty"`
}

type osintOutput struct {
	Target           string                     `json:"target"`
	DNS              model.DNSRecord            `json:"dns"`
	WHOIS            map[string]any             `json:"whois,omitempty"`
	Subdomains       []string                   `json:"subdomains"`
	Emails           []string                   `json:"emails"`
	Dorks            []string                   `json:"dorks,omitempty"`
	Employees        []osintEmployee            `json:"employees,omitempty"`
	TechStack        []string                   `json:"tech_stack,omitempty"`
	Screenshots      []string                   `json:"screenshots,omitempty"`
	SecretIndicators []osintSecretIndicator     `json:"secret_indicators,omitempty"`
	Sources          map[string]json.RawMessage `json:"sources,omitempty"`
	Warnings         []string                   `json:"warnings"`
}

func mergeOSINT(left, right osintOutput) osintOutput {
	if right.Target != "" {
		left.Target = right.Target
	}
	if right.DNS.Name != "" {
		left.DNS = right.DNS
	}
	if len(right.WHOIS) > 0 {
		left.WHOIS = right.WHOIS
	}
	left.Subdomains = utils.Strings(append(left.Subdomains, right.Subdomains...))
	left.Emails = utils.Strings(append(left.Emails, right.Emails...))
	left.Dorks = stableStrings(append(left.Dorks, right.Dorks...))
	left.Employees = mergeOSINTEmployees(left.Employees, right.Employees)
	left.TechStack = stableStrings(append(left.TechStack, right.TechStack...))
	left.Screenshots = stableStrings(append(left.Screenshots, right.Screenshots...))
	left.SecretIndicators = append(left.SecretIndicators, right.SecretIndicators...)
	if len(right.Sources) > 0 {
		left.Sources = right.Sources
	}
	left.Warnings = utils.Strings(append(left.Warnings, right.Warnings...))
	return left
}

func mergeOSINTEmployees(left, right []osintEmployee) []osintEmployee {
	byIdentity := make(map[string]osintEmployee, len(left)+len(right))
	for _, employee := range append(append([]osintEmployee(nil), left...), right...) {
		employee.Name = strings.TrimSpace(employee.Name)
		employee.URL = strings.TrimSpace(employee.URL)
		if employee.Name == "" && employee.URL == "" {
			continue
		}
		identity := strings.ToLower(employee.URL)
		if identity == "" {
			identity = strings.ToLower(employee.Name + "\x00" + employee.Headline)
		}
		if _, exists := byIdentity[identity]; !exists {
			byIdentity[identity] = employee
		}
	}
	output := make([]osintEmployee, 0, len(byIdentity))
	for _, employee := range byIdentity {
		output = append(output, employee)
	}
	sort.Slice(output, func(i, j int) bool {
		if output[i].Name != output[j].Name {
			return output[i].Name < output[j].Name
		}
		return output[i].URL < output[j].URL
	})
	return output
}

func stableStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	output := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, exists := seen[value]; !exists {
			seen[value] = struct{}{}
			output = append(output, value)
		}
	}
	sort.Strings(output)
	return output
}

func osintSecretLines(indicators []osintSecretIndicator) []string {
	seen := make(map[string]struct{}, len(indicators))
	lines := make([]string, 0, len(indicators))
	for _, indicator := range indicators {
		parts := []string{indicator.Source, indicator.Indicator}
		if indicator.Repository != "" {
			parts = append(parts, indicator.Repository)
		}
		if indicator.Path != "" {
			parts = append(parts, indicator.Path)
		}
		line := strings.Join(parts, ":") + " [REDACTED]"
		if _, exists := seen[line]; !exists {
			seen[line] = struct{}{}
			lines = append(lines, line)
		}
	}
	sort.Strings(lines)
	return lines
}
func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
func hostAddresses(hosts []model.Host) []netip.Addr {
	output := make([]netip.Addr, 0, len(hosts))
	for _, host := range hosts {
		if address, err := netip.ParseAddr(host.IP); err == nil {
			output = append(output, address)
		}
	}
	return output
}
func parallelProbe(ctx context.Context, client *httpx.Client, targets []string, workers int) []model.WebResult {
	return parallelWeb(ctx, targets, workers, client.Probe)
}
func parallelProbeHead(ctx context.Context, client *httpx.Client, targets []string, workers int) []model.WebResult {
	return parallelWeb(ctx, targets, workers, client.ProbeHead)
}
func parallelProbeRateLimited(ctx context.Context, client *httpx.Client, targets []string, workers, rate int) []model.WebResult {
	return parallelWebRateLimited(ctx, targets, workers, rate, client.Probe)
}
func parallelProbeHeadRateLimited(ctx context.Context, client *httpx.Client, targets []string, workers, rate int) []model.WebResult {
	return parallelWebRateLimited(ctx, targets, workers, rate, client.ProbeHead)
}
func parallelWeb(ctx context.Context, targets []string, workers int, probe func(context.Context, string) model.WebResult) []model.WebResult {
	if workers < 1 {
		workers = 1
	}
	jobs := make(chan string)
	results := make(chan model.WebResult, len(targets))
	var group sync.WaitGroup
	for i := 0; i < min(workers, 50); i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			for target := range jobs {
				select {
				case results <- probe(ctx, target):
				case <-ctx.Done():
					return
				}
			}
		}()
	}
	go func() {
		defer func() { close(jobs); group.Wait(); close(results) }()
		for _, target := range targets {
			select {
			case jobs <- target:
			case <-ctx.Done():
				return
			}
		}
	}()
	output := make([]model.WebResult, 0, len(targets))
	for result := range results {
		output = append(output, result)
	}
	sort.Slice(output, func(i, j int) bool { return output[i].URL < output[j].URL })
	return output
}

// parallelWebRateLimited uses one ticker shared by all workers. It retains the
// bounded worker pool while making cloud and takeover HTTP probes obey the
// same configured requests-per-second limit as Phase 2 DNS operations.
func parallelWebRateLimited(ctx context.Context, targets []string, workers, rate int, probe func(context.Context, string) model.WebResult) []model.WebResult {
	if len(targets) == 0 {
		return nil
	}
	if rate < 1 {
		return parallelWeb(ctx, targets, workers, probe)
	}
	if workers < 1 {
		workers = 1
	}
	interval := time.Second / time.Duration(rate)
	if interval < time.Microsecond {
		interval = time.Microsecond
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	jobs := make(chan string)
	results := make(chan model.WebResult, len(targets))
	var group sync.WaitGroup
	for i := 0; i < min(workers, 50); i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			for target := range jobs {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
				}
				select {
				case results <- probe(ctx, target):
				case <-ctx.Done():
					return
				}
			}
		}()
	}
	go func() {
		defer func() { close(jobs); group.Wait(); close(results) }()
		for _, target := range targets {
			select {
			case jobs <- target:
			case <-ctx.Done():
				return
			}
		}
	}()
	output := make([]model.WebResult, 0, len(targets))
	for result := range results {
		output = append(output, result)
	}
	sort.Slice(output, func(i, j int) bool { return output[i].URL < output[j].URL })
	return output
}
func phaseSelection(phases, skip string) (map[int]bool, error) {
	selected := map[int]bool{}
	for _, item := range strings.Split(phases, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		pieces := strings.Split(item, "-")
		start, end := 0, 0
		var err error
		start, err = strconv.Atoi(pieces[0])
		if err != nil {
			return nil, fmt.Errorf("invalid phase %q", item)
		}
		end = start
		if len(pieces) == 2 {
			end, err = strconv.Atoi(pieces[1])
			if err != nil {
				return nil, fmt.Errorf("invalid phase %q", item)
			}
		}
		if len(pieces) > 2 || start < 0 || end > 10 || start > end {
			return nil, fmt.Errorf("phase %q is outside 0-10", item)
		}
		for phase := start; phase <= end; phase++ {
			selected[phase] = true
		}
	}
	for _, item := range strings.Split(skip, ",") {
		if strings.TrimSpace(item) == "" {
			continue
		}
		value, err := strconv.Atoi(strings.TrimSpace(item))
		if err != nil || value < 0 || value > 10 {
			return nil, fmt.Errorf("invalid skipped phase %q", item)
		}
		delete(selected, value)
	}
	return selected, nil
}
func safeName(value string) string {
	value = strings.NewReplacer(":", "_", "/", "_", "?", "_", "&", "_").Replace(value)
	if len(value) > 100 {
		return value[:100]
	}
	return value
}
func trailingNewline(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return "\n"
}
func contains(values []string, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}
func sortedUnique(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	output := make([]string, 0, len(values))
	for _, value := range values {
		if value != "" {
			if _, found := seen[value]; !found {
				seen[value] = struct{}{}
				output = append(output, value)
			}
		}
	}
	sort.Strings(output)
	return output
}
func min(left, right int) int {
	if left < right {
		return left
	}
	return right
}
func max(left, right int) int {
	if left > right {
		return left
	}
	return right
}
func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
