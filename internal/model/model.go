// Package model defines the stable data contracts shared by reconx phases.
package model

import (
	"net/netip"
	"sort"
	"sync"
	"time"
)

const SchemaVersion = "1.0"

type TargetKind string

const (
	TargetDomain TargetKind = "domain"
	TargetIP     TargetKind = "ip"
	TargetCIDR   TargetKind = "cidr"
	TargetURL    TargetKind = "url"
)

type TargetProfile struct {
	Input        string      `json:"input"`
	Kind         TargetKind  `json:"kind"`
	Hostname     string      `json:"hostname,omitempty"`
	URL          string      `json:"url,omitempty"`
	CIDR         string      `json:"cidr,omitempty"`
	IPs          []string    `json:"ips"`
	ReverseNames []string    `json:"reverse_names,omitempty"`
	CloudProvider string     `json:"cloud_provider,omitempty"`
	ResolvedAt   time.Time   `json:"resolved_at"`
}

type Host struct {
	IP          string   `json:"ip"`
	Names       []string `json:"names,omitempty"`
	ReverseDNS  string   `json:"reverse_dns,omitempty"`
	OpenTCP     []int    `json:"open_tcp,omitempty"`
	OpenUDP     []int    `json:"open_udp,omitempty"`
	Services    []Service `json:"services,omitempty"`
	Reachable   bool     `json:"reachable"`
}

type Service struct {
	Host      string `json:"host"`
	Port      int    `json:"port"`
	Transport string `json:"transport"`
	Name      string `json:"name"`
	Banner    string `json:"banner,omitempty"`
	TLS       bool   `json:"tls,omitempty"`
	TLSVersion string `json:"tls_version,omitempty"`
	TLSCipher string `json:"tls_cipher,omitempty"`
	Version   string `json:"version,omitempty"`
}

type DNSRecord struct {
	Name   string   `json:"name"`
	A      []string `json:"a,omitempty"`
	AAAA   []string `json:"aaaa,omitempty"`
	CNAME  string   `json:"cname,omitempty"`
	MX     []string `json:"mx,omitempty"`
	NS     []string `json:"ns,omitempty"`
	SOA    []string `json:"soa,omitempty"`
	TXT    []string `json:"txt,omitempty"`
	SRV    []string `json:"srv,omitempty"`
	CAA    []string `json:"caa,omitempty"`
	NAPTR  []string `json:"naptr,omitempty"`
	Lookup []string `json:"lookup_errors,omitempty"`
}

type WebResult struct {
	URL          string            `json:"url"`
	FinalURL     string            `json:"final_url,omitempty"`
	Host         string            `json:"host"`
	StatusCode   int               `json:"status_code"`
	Title        string            `json:"title,omitempty"`
	Headers      map[string]string `json:"headers,omitempty"`
	Technologies []string          `json:"technologies,omitempty"`
	Links        []string          `json:"links,omitempty"`
	Forms        []WebForm         `json:"forms,omitempty"`
	APIEndpoints []string          `json:"api_endpoints,omitempty"`
	Cookies      []CookieInfo      `json:"cookies,omitempty"`
	Body         string            `json:"-"`
	TLS          *TLSInfo          `json:"tls,omitempty"`
	Error        string            `json:"error,omitempty"`
}

type WebForm struct {
	Action string   `json:"action,omitempty"`
	Method string   `json:"method,omitempty"`
	Fields []string `json:"fields,omitempty"`
}

type CookieInfo struct {
	Name     string `json:"name"`
	Secure   bool   `json:"secure"`
	HTTPOnly bool   `json:"http_only"`
	SameSite string `json:"same_site,omitempty"`
}

type TLSInfo struct {
	Version      string   `json:"version,omitempty"`
	Cipher       string   `json:"cipher,omitempty"`
	Issuer       string   `json:"issuer,omitempty"`
	Subject      string   `json:"subject,omitempty"`
	DNSNames     []string `json:"dns_names,omitempty"`
	NotAfter     string   `json:"not_after,omitempty"`
	SelfSigned   bool     `json:"self_signed,omitempty"`
}

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

type Finding struct {
	ID          string   `json:"id"`
	Severity    Severity `json:"severity"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Evidence    string   `json:"evidence,omitempty"`
	Asset       string   `json:"asset,omitempty"`
	URL         string   `json:"url,omitempty"`
	MITRE       []string `json:"mitre,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
	Confidence  string   `json:"confidence"`
	Source      string   `json:"source"`
}

type PhaseResult struct {
	Number   int           `json:"number"`
	Name     string        `json:"name"`
	Status   string        `json:"status"`
	Duration time.Duration `json:"duration"`
	Warning  string        `json:"warning,omitempty"`
}

type RiskSummary struct {
	Score         int            `json:"score"`
	Level         Severity       `json:"level"`
	BySeverity    map[Severity]int `json:"by_severity"`
	HostScores    map[string]int `json:"host_scores"`
	TotalFindings int            `json:"total_findings"`
}

type Report struct {
	SchemaVersion string        `json:"schema_version"`
	GeneratedAt   time.Time     `json:"generated_at"`
	Target        TargetProfile `json:"target"`
	Hosts         []Host        `json:"hosts"`
	DNS           []DNSRecord   `json:"dns,omitempty"`
	Web           []WebResult   `json:"web,omitempty"`
	Findings      []Finding     `json:"findings"`
	Risk          RiskSummary   `json:"risk"`
	Phases        []PhaseResult `json:"phases"`
	Warnings      []string      `json:"warnings,omitempty"`
}

// State is phase-owned shared state. Methods copy and normalize data so
// concurrent workers never mutate exported slices directly.
type State struct {
	mu         sync.RWMutex
	Target     TargetProfile
	Hosts      map[string]*Host
	DNS        map[string]DNSRecord
	Subdomains map[string]struct{}
	Web        map[string]WebResult
	Findings   []Finding
	Warnings   []string
	Phases     []PhaseResult
}

func NewState(profile TargetProfile) *State {
	return &State{
		Target: profile, Hosts: make(map[string]*Host), DNS: make(map[string]DNSRecord),
		Subdomains: make(map[string]struct{}), Web: make(map[string]WebResult),
	}
}

func (s *State) AddHost(ip netip.Addr, name string) {
	if !ip.IsValid() {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := ip.String()
	h, ok := s.Hosts[key]
	if !ok {
		h = &Host{IP: key}
		s.Hosts[key] = h
	}
	if name != "" && !contains(h.Names, name) {
		h.Names = append(h.Names, name)
		sort.Strings(h.Names)
	}
}

func (s *State) AddSubdomain(name string) {
	if name == "" {
		return
	}
	s.mu.Lock()
	s.Subdomains[name] = struct{}{}
	s.mu.Unlock()
}

func (s *State) SetReverseDNS(host, reverse string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	value, found := s.Hosts[host]
	if !found { value = &Host{IP: host}; s.Hosts[host] = value }
	value.ReverseDNS = reverse
}

func (s *State) MarkReachable(host string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	value, found := s.Hosts[host]
	if !found { value = &Host{IP: host}; s.Hosts[host] = value }
	value.Reachable = true
}

func (s *State) AddOpenPort(host string, port int, udp bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	value, found := s.Hosts[host]
	if !found { value = &Host{IP: host}; s.Hosts[host] = value }
	ports := &value.OpenTCP
	if udp { ports = &value.OpenUDP }
	if !containsInt(*ports, port) { *ports = append(*ports, port); sort.Ints(*ports) }
	value.Reachable = true
}

func (s *State) AddService(service Service) {
	s.mu.Lock()
	defer s.mu.Unlock()
	value, found := s.Hosts[service.Host]
	if !found { value = &Host{IP: service.Host}; s.Hosts[service.Host] = value }
	for _, existing := range value.Services { if existing.Port == service.Port && existing.Transport == service.Transport { return } }
	value.Services = append(value.Services, service)
	sort.Slice(value.Services, func(i, j int) bool { return value.Services[i].Port < value.Services[j].Port })
}

func (s *State) SubdomainList() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	output := make([]string, 0, len(s.Subdomains))
	for value := range s.Subdomains { output = append(output, value) }
	sort.Strings(output)
	return output
}

func (s *State) HostList() []Host {
	_, hosts, _, _, _, _, _ := s.Snapshot()
	return hosts
}

func (s *State) AddDNS(record DNSRecord) {
	s.mu.Lock()
	s.DNS[record.Name] = record
	s.mu.Unlock()
}

func (s *State) AddWeb(result WebResult) {
	s.mu.Lock()
	s.Web[result.URL] = result
	s.mu.Unlock()
}

func (s *State) AddFinding(f Finding) {
	s.mu.Lock()
	s.Findings = append(s.Findings, f)
	s.mu.Unlock()
}

func (s *State) ReplaceFindings(findings []Finding) {
	s.mu.Lock()
	s.Findings = append([]Finding(nil), findings...)
	s.mu.Unlock()
}

func (s *State) AddWarning(warning string) {
	if warning == "" {
		return
	}
	s.mu.Lock()
	s.Warnings = append(s.Warnings, warning)
	s.mu.Unlock()
}

func (s *State) AddPhase(result PhaseResult) {
	s.mu.Lock()
	s.Phases = append(s.Phases, result)
	s.mu.Unlock()
}

func (s *State) Snapshot() (TargetProfile, []Host, []DNSRecord, []WebResult, []Finding, []string, []PhaseResult) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	hosts := make([]Host, 0, len(s.Hosts))
	for _, h := range s.Hosts {
		value := *h
		value.Names = append([]string(nil), h.Names...)
		value.OpenTCP = append([]int(nil), h.OpenTCP...)
		value.OpenUDP = append([]int(nil), h.OpenUDP...)
		value.Services = append([]Service(nil), h.Services...)
		hosts = append(hosts, value)
	}
	sort.Slice(hosts, func(i, j int) bool { return hosts[i].IP < hosts[j].IP })
	dns := make([]DNSRecord, 0, len(s.DNS))
	for _, d := range s.DNS { dns = append(dns, d) }
	sort.Slice(dns, func(i, j int) bool { return dns[i].Name < dns[j].Name })
	web := make([]WebResult, 0, len(s.Web))
	for _, w := range s.Web { web = append(web, w) }
	sort.Slice(web, func(i, j int) bool { return web[i].URL < web[j].URL })
	findings := append([]Finding(nil), s.Findings...)
	warnings := append([]string(nil), s.Warnings...)
	phases := append([]PhaseResult(nil), s.Phases...)
	return s.Target, hosts, dns, web, findings, warnings, phases
}

func contains(values []string, value string) bool {
	for _, candidate := range values { if candidate == value { return true } }
	return false
}
func containsInt(values []int, value int) bool {
	for _, candidate := range values { if candidate == value { return true } }
	return false
}
