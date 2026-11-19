package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadDocumentedPlanConfigurationShape(t *testing.T) {
	content := `api_keys:
  shodan: "a"
  censys: "b"
  censys_id: "censys-id"
  censys_secret: "censys-secret"
  virustotal: "c"
  urlscan: "d"
  serpapi: "e"
  github: "github-token"
  gitlab: "gitlab-token"
  hibp: "hibp-key"
  securitytrails: "securitytrails-key"
  viewdns: "viewdns-key"
  ipinfo: "ipinfo-token"
wordlists:
  subdomains: "/tmp/subdomains.txt"
  directories: "/tmp/directories.txt"
  usernames: "/tmp/users.txt"
  passwords: "/tmp/passwords.txt"
scanning:
  rate: 1000
  timeout_ms: 5000
  workers: 100
  ports: "top-1000"
  udp_ports: "top-100"
attack_surface:
  cloud_assets: true
  max_cloud_candidates: 800
  takeover_verify: true
  max_takeover_checks: 1200
  subdomain_permutations: true
  max_subdomain_words: 6000
  max_permutations: 20000
osint:
  axfr: false
  social_enum: true
web:
  crawl_depth: 3
  max_urls: 1000
  respect_robots: false
  user_agent: "reconx"
reporting:
  show_secrets: false
  html_theme: "dark"
  pdf: true
external_tools:
  nmap: "/usr/bin/nmap"
  masscan: "/usr/bin/masscan"
  nuclei: "/usr/local/bin/nuclei"
  nikto: "/usr/bin/nikto"
  sqlmap: "/usr/bin/sqlmap"
  wpscan: "/usr/bin/wpscan"
  testssl: "/usr/bin/testssl.sh"
  enum4linux: "/usr/bin/enum4linux"
  snmpwalk: "/usr/bin/snmpwalk"
  ldapsearch: "/usr/bin/ldapsearch"
  sherlock: "/usr/bin/sherlock"
`
	path := filepath.Join(t.TempDir(), "reconx.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	value, err := LoadFile(path, Default())
	if err != nil {
		t.Fatal(err)
	}
	if value.NmapPath != "/usr/bin/nmap" || !value.PDFEnabled || value.UsernameWordlist == "" || value.PasswordWordlist == "" || value.CensysID != "censys-id" || value.HIBPKey != "hibp-key" || !value.SocialEnum || value.SherlockPath != "/usr/bin/sherlock" || !value.CloudAssets || !value.TakeoverVerify || value.SubdomainMaxWords != 6000 || value.SubdomainMaxPermutations != 20000 || value.CloudAssetMaxCandidates != 800 || value.TakeoverMaxChecks != 1200 {
		t.Fatalf("plan config not loaded: %#v", value)
	}
}
