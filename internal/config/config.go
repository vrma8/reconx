// Package config contains runtime limits and a deliberately small YAML reader.
// Keeping the configuration dependency-free preserves static CGO-free builds.
package config

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Authorized               bool
	Workspace                string
	Phases                   string
	Skip                     string
	Fast                     bool
	Deep                     bool
	Rate                     int
	Timeout                  time.Duration
	Workers                  int
	Retries                  int
	MaxProbes                int
	UnsafeLargeScan          bool
	FullPorts                bool
	UDPPorts                 string
	UDP                      bool
	Syn                      bool
	Masscan                  bool
	ICMP                     bool
	NmapServiceScan          bool
	NmapOSScan               bool
	NmapVulnScan             bool
	NmapArgs                 string
	ServiceEnum              bool
	ServiceDetails           bool
	HostEnrichment           bool
	HeaderScore              bool
	SRIChecks                bool
	TLSAssessment            bool
	ActiveWAF                bool
	ParameterFuzzing         bool
	SensitiveFiles           bool
	SensitiveWordlist        string
	MaxSensitivePaths        int
	ActiveChecks             bool
	CloudAssets              bool
	TakeoverVerify           bool
	OSINT                    bool
	SubdomainBrute           bool
	SubdomainPermutations    bool
	SubdomainWordlist        string
	SubdomainMaxWords        int
	SubdomainMaxPermutations int
	CloudAssetMaxCandidates  int
	TakeoverMaxChecks        int
	UsernameWordlist         string
	PasswordWordlist         string
	CrawlDepth               int
	MaxURLs                  int
	RespectRobots            bool
	ContentDiscovery         bool
	APIDiscovery             bool
	DirectoryWordlist        string
	JSAnalysis               bool
	Screenshots              bool
	WAFDetection             bool
	TestSSL                  bool
	Nuclei                   bool
	Nikto                    bool
	SQLMap                   bool
	WPScan                   bool
	NVD                      bool
	CVEDB                    string
	NLP                      bool
	PythonDir                string
	HTML                     string
	JSON                     string
	CSV                      string
	PDF                      string
	Diff                     string
	ShowSecrets              bool
	HTMLTheme                string
	PDFEnabled               bool
	SystemdUnit              bool
	Verbose                  bool
	Quiet                    bool
	ShodanKey                string
	CensysKey                string
	CensysID                 string
	CensysSecret             string
	VTKey                    string
	URLScanKey               string
	SerpKey                  string
	GitHubToken              string
	GitLabToken              string
	HIBPKey                  string
	SecurityTrailsKey        string
	ViewDNSKey               string
	IPInfoToken              string
	OSINTAXFR                bool
	SocialEnum               bool
	UserAgent                string
	NmapPath                 string
	MasscanPath              string
	NucleiPath               string
	NiktoPath                string
	SQLMapPath               string
	WPScanPath               string
	TestSSLPath              string
	Enum4LinuxPath           string
	SNMPWalkPath             string
	LDAPSearchPath           string
	SMBClientPath            string
	SherlockPath             string
}

func Default() Config {
	return Config{
		Workspace: "", Phases: "0-10", Rate: 1000, Timeout: 500 * time.Millisecond,
		Workers: 100, Retries: 2, MaxProbes: 300000, OSINT: true, OSINTAXFR: true, SocialEnum: true,
		SubdomainBrute: true, SubdomainPermutations: true, CloudAssets: true, TakeoverVerify: true,
		SubdomainMaxWords: 5000, SubdomainMaxPermutations: 10000, CloudAssetMaxCandidates: 500, TakeoverMaxChecks: 0,
		CrawlDepth: 3, MaxURLs: 1000, APIDiscovery: true, NLP: true, PythonDir: "python", UserAgent: "reconx/1.0 (+authorized-security-assessment)",
		HostEnrichment: true, HeaderScore: true, SRIChecks: true, TLSAssessment: true,
		MaxSensitivePaths: 200,
	}
}

func (c Config) Validate() error {
	if c.Rate < 1 {
		return fmt.Errorf("rate must be at least 1")
	}
	if c.Workers < 1 || c.Workers > 5000 {
		return fmt.Errorf("workers must be between 1 and 5000")
	}
	if c.Retries < 0 || c.Retries > 5 {
		return fmt.Errorf("retries must be between 0 and 5")
	}
	if c.Timeout < 50*time.Millisecond || c.Timeout > 5*time.Minute {
		return fmt.Errorf("timeout must be between 50ms and 5m")
	}
	if c.MaxProbes < 1 {
		return fmt.Errorf("max-probes must be at least 1")
	}
	if c.SubdomainMaxWords < 1 {
		return fmt.Errorf("subdomain max words must be at least 1")
	}
	if c.SubdomainMaxPermutations < 1 {
		return fmt.Errorf("subdomain max permutations must be at least 1")
	}
	if c.CloudAssetMaxCandidates < 1 {
		return fmt.Errorf("cloud asset max candidates must be at least 1")
	}
	// Zero means inspect every discovered CNAME. The overall phase probe budget
	// remains enforced, so this does not make the authorized run unbounded.
	if c.TakeoverMaxChecks < 0 {
		return fmt.Errorf("takeover max checks must be zero (all) or positive")
	}
	if c.CrawlDepth < 0 || c.CrawlDepth > 10 {
		return fmt.Errorf("crawl-depth must be between 0 and 10")
	}
	if c.MaxURLs < 1 {
		return fmt.Errorf("max-urls must be at least 1")
	}
	if c.MaxSensitivePaths < 1 || c.MaxSensitivePaths > 2000 {
		return fmt.Errorf("max-sensitive-paths must be between 1 and 2000")
	}
	return nil
}

// LoadFile supports the documented nested key/value YAML shape. It purposely
// accepts only scalar values: reconx config does not require YAML features
// that would justify increasing binary size with a parser dependency.
func LoadFile(path string, base Config) (Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return base, err
	}
	defer file.Close()
	section := ""
	scanner := bufio.NewScanner(file)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		raw := strings.TrimSpace(strings.SplitN(scanner.Text(), "#", 2)[0])
		if raw == "" || raw == "---" {
			continue
		}
		if !strings.Contains(raw, ":") {
			return base, fmt.Errorf("config %s:%d: expected key: value", path, lineNo)
		}
		indent := len(scanner.Text()) - len(strings.TrimLeft(scanner.Text(), " \t"))
		parts := strings.SplitN(raw, ":", 2)
		key := strings.TrimSpace(parts[0])
		value := strings.Trim(strings.TrimSpace(parts[1]), "\"'")
		if value == "" {
			if indent == 0 {
				section = key
				continue
			}
			return base, fmt.Errorf("config %s:%d: empty scalar", path, lineNo)
		}
		fullKey := key
		if indent > 0 && section != "" {
			fullKey = section + "." + key
		}
		if err := apply(&base, fullKey, value); err != nil {
			return base, fmt.Errorf("config %s:%d: %w", path, lineNo, err)
		}
	}
	if err := scanner.Err(); err != nil {
		return base, err
	}
	return base, base.Validate()
}

func apply(c *Config, key, value string) error {
	integer := func(destination *int) error {
		parsed, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("%s must be an integer", key)
		}
		*destination = parsed
		return nil
	}
	boolean := func(destination *bool) error {
		parsed, err := strconv.ParseBool(value)
		if err != nil {
			return fmt.Errorf("%s must be true or false", key)
		}
		*destination = parsed
		return nil
	}
	switch key {
	case "api_keys.shodan":
		c.ShodanKey = value
	case "api_keys.censys":
		c.CensysKey = value
	case "api_keys.censys_id":
		c.CensysID = value
	case "api_keys.censys_secret":
		c.CensysSecret = value
	case "api_keys.virustotal":
		c.VTKey = value
	case "api_keys.urlscan":
		c.URLScanKey = value
	case "api_keys.serpapi":
		c.SerpKey = value
	case "api_keys.github":
		c.GitHubToken = value
	case "api_keys.gitlab":
		c.GitLabToken = value
	case "api_keys.hibp":
		c.HIBPKey = value
	case "api_keys.securitytrails":
		c.SecurityTrailsKey = value
	case "api_keys.viewdns":
		c.ViewDNSKey = value
	case "api_keys.ipinfo":
		c.IPInfoToken = value
	case "wordlists.subdomains":
		c.SubdomainWordlist = value
	case "wordlists.directories":
		c.DirectoryWordlist = value
	case "wordlists.usernames":
		c.UsernameWordlist = value
	case "wordlists.passwords":
		c.PasswordWordlist = value
	case "scanning.rate":
		return integer(&c.Rate)
	case "scanning.timeout_ms":
		var ms int
		if err := integer(&ms); err != nil {
			return err
		}
		c.Timeout = time.Duration(ms) * time.Millisecond
	case "scanning.workers":
		return integer(&c.Workers)
	case "scanning.retries":
		return integer(&c.Retries)
	case "scanning.max_probes":
		return integer(&c.MaxProbes)
	case "scanning.ports":
		if value == "full" || value == "1-65535" {
			c.FullPorts = true
		}
	case "scanning.udp_ports":
		c.UDPPorts = value
		c.UDP = true
	case "scanning.masscan":
		return boolean(&c.Masscan)
	case "scanning.icmp":
		return boolean(&c.ICMP)
	case "scanning.service_enum":
		return boolean(&c.ServiceEnum)
	case "scanning.service_details":
		return boolean(&c.ServiceDetails)
	case "attack_surface.cloud_assets":
		return boolean(&c.CloudAssets)
	case "attack_surface.max_cloud_candidates":
		return integer(&c.CloudAssetMaxCandidates)
	case "attack_surface.takeover_verify":
		return boolean(&c.TakeoverVerify)
	case "attack_surface.max_takeover_checks":
		return integer(&c.TakeoverMaxChecks)
	case "attack_surface.subdomain_permutations":
		return boolean(&c.SubdomainPermutations)
	case "attack_surface.max_subdomain_words":
		return integer(&c.SubdomainMaxWords)
	case "attack_surface.max_permutations":
		return integer(&c.SubdomainMaxPermutations)
	case "osint.axfr":
		return boolean(&c.OSINTAXFR)
	case "osint.social_enum":
		return boolean(&c.SocialEnum)
	case "osint.host_enrichment":
		return boolean(&c.HostEnrichment)
	case "web.crawl_depth":
		return integer(&c.CrawlDepth)
	case "web.max_urls":
		return integer(&c.MaxURLs)
	case "web.respect_robots":
		return boolean(&c.RespectRobots)
	case "web.content_discovery":
		return boolean(&c.ContentDiscovery)
	case "web.api_discovery":
		return boolean(&c.APIDiscovery)
	case "web.js_analysis":
		return boolean(&c.JSAnalysis)
	case "web.screenshots":
		return boolean(&c.Screenshots)
	case "web.waf_detection":
		return boolean(&c.WAFDetection)
	case "web.header_score":
		return boolean(&c.HeaderScore)
	case "web.sri_checks":
		return boolean(&c.SRIChecks)
	case "web.tls_assessment":
		return boolean(&c.TLSAssessment)
	case "web.active_waf":
		return boolean(&c.ActiveWAF)
	case "web.parameter_fuzzing":
		return boolean(&c.ParameterFuzzing)
	case "web.sensitive_files":
		return boolean(&c.SensitiveFiles)
	case "web.sensitive_wordlist":
		c.SensitiveWordlist = value
	case "web.max_sensitive_paths":
		return integer(&c.MaxSensitivePaths)
	case "web.testssl":
		return boolean(&c.TestSSL)
	case "web.user_agent":
		c.UserAgent = value
	case "vulnerability.active_checks":
		return boolean(&c.ActiveChecks)
	case "vulnerability.nvd":
		return boolean(&c.NVD)
	case "vulnerability.cve_db":
		c.CVEDB = value
	case "secrets.nlp":
		return boolean(&c.NLP)
	case "reporting.show_secrets":
		return boolean(&c.ShowSecrets)
	case "reporting.html_theme":
		c.HTMLTheme = value
	case "reporting.pdf":
		return boolean(&c.PDFEnabled)
	case "reporting.systemd_unit":
		return boolean(&c.SystemdUnit)
	case "external_tools.nmap":
		c.NmapPath = value
	case "external_tools.masscan":
		c.MasscanPath = value
	case "external_tools.nuclei":
		c.NucleiPath = value
	case "external_tools.nikto":
		c.NiktoPath = value
	case "external_tools.sqlmap":
		c.SQLMapPath = value
	case "external_tools.wpscan":
		c.WPScanPath = value
	case "external_tools.testssl":
		c.TestSSLPath = value
	case "external_tools.enum4linux":
		c.Enum4LinuxPath = value
	case "external_tools.snmpwalk":
		c.SNMPWalkPath = value
	case "external_tools.ldapsearch":
		c.LDAPSearchPath = value
	case "external_tools.smbclient":
		c.SMBClientPath = value
	case "external_tools.sherlock":
		c.SherlockPath = value
	default:
		return fmt.Errorf("unknown setting %q", key)
	}
	return nil
}
