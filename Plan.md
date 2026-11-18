
Build a Go command-line tool called `reconx` — an all-in-one automated reconnaissance engine for Kali Linux. It takes a single target (IP, CIDR, domain, or URL) and runs the ENTIRE recon phase of a penetration test end-to-end, producing a unified workspace of findings, a risk-scored report, and machine-readable exports.

═══════════════════════════════════════════════════════════════
LANGUAGE STRATEGY — WHERE EACH LANGUAGE IS USED AND WHY
═══════════════════════════════════════════════════════════════

GO (the core — 90% of the codebase)
──────────────────────────────────────

- CLI entry point, argument parsing, orchestration engine
- All concurrent I/O: DNS resolution, HTTP probing, port scanning,
  subdomain enumeration, web crawling, banner grabbing
- Workspace management (file I/O, SQLite, deduplication, diffing)
- Report generation (terminal, HTML, JSON, CSV, PDF via wkhtmltopdf)
- Port scanner: TCP connect (all platforms) + TCP SYN stealth
  (Linux, via AF_PACKET raw socket — proven to reach 1.3M+ pps in Go,
  sufficient for recon; no C needed)
- Web crawler and content discovery (goroutine-based, HTTP/1.1 + HTTP/2)
- Subdomain brute-force engine (massdns-style, async DNS)
- Cloud asset enumeration (S3 buckets, Azure, GCP, DigitalOcean)
- Subdomain takeover detection
- Risk scoring and correlation engine
- JSON/CSV/HTML output serializers

WHY GO HERE: Recon is I/O-bound. Go's goroutines give 10,000+ concurrent
connections with zero boilerplate. Single static binary (CGO_ENABLED=0).
The entire ProjectDiscovery toolchain (subfinder, httpx, naabu, nuclei,
katana, dnsx, ffuf) is Go — we either import their libraries or shell
out to their binaries. AF_PACKET in Go is production-proven (see
altshiftab/port_scanner, gomap). No C needed for recon-level scanning.

PYTHON (embedded subprocess modules — 8% of the codebase)
──────────────────────────────────────────────────────────

- OSINT API integration (Shodan, Censys, VirusTotal, urlscan.io,
  Hunter.io, HaveIBeenPwned, GitHub code search, Pastebin, etc.)
  → Python has the richest SDK ecosystem for these (shodan, censys,
  python-whois, dnspython, httpx, requests, beautifulsoup4).
- Web scraping of OSINT sources (LinkedIn, GitHub, Shodan HTML,
  certificate transparency logs) where Go's HTML parsing is weaker.
- NLP / entity extraction from scraped text (spaCy, regex patterns
  for emails, phones, internal hostnames, API keys).
- Headless browser automation for JS-heavy pages (Playwright/Selenium)
  → screenshots, rendered content, JS endpoint extraction.
- Metagoofil-style document metadata extraction (PDF, DOCX, PPT).
- Social media / username enumeration (sherlock-style, 300+ sites).

WHY PYTHON HERE: The OSINT/scraping/NLP ecosystem in Python is
unmatched. Go has no good NLP stack, no Playwright bindings, and
the OSINT API SDKs are Python-first. We run these as isolated
subprocesses (python3 -m reconx_osint <phase></phase> --target X --out json)
and parse their JSON stdout. This keeps the Go core clean and lets
Python modules be updated independently.

C/C++ (NOT used in the core — optional external tools only)
────────────────────────────────────────────────────────────

- We do NOT write C/C++ code. The Go AF_PACKET scanner is sufficient
  for recon (1.3M pps vs Masscan's 10M pps — irrelevant for a single
  target or /24).
- For extreme performance (scanning /8 or /16 at 10M+ pps), the tool
  optionally shells out to `masscan` (C) as a pre-scan to find open
  ports, then Go handles service detection and enumeration.
- For protocol-level exploitation (SMB, LDAP, RDP enumeration),
  the tool shells out to existing C tools (enum4linux, smbclient,
  ldapsearch, nmap NSE scripts) rather than reimplementing them.
- For packet-level analysis (if the user captures traffic),
  shell out to `tshark`/`tcpdump` (C) for pcap parsing.

WHY NOT C IN THE CORE: Writing raw-socket C for a recon tool is
overkill. Go's AF_PACKET is 95% as fast with 10% the code. C adds
memory-safety risk, build complexity, and cgo dependencies that
break the single-static-binary goal.

═══════════════════════════════════════════════════════════════
PHASES — THE FULL RECON PIPELINE
═══════════════════════════════════════════════════════════════

The tool runs phases in strict order. Each phase feeds discovered
assets into the next. All output lands in a single workspace directory.

PHASE 0 — TARGET INTAKE & VALIDATION
─────────────────────────────────────

- Accept: single IP, CIDR (up to /16), domain, URL, or file of targets
- Validate: is the target in scope? (user must confirm with --i-am-authorized)
- Resolve: domain → IP(s), IP → reverse DNS, URL → domain + IP
- Detect: is this a cloud IP? (AWS, GCP, Azure, DigitalOcean, OVH)
- Initialize workspace: ./reconx_workspaces/<target></target>_<timestamp></timestamp>/
  Subdirs: 01_osint/ 02_subdomains/ 03_hosts/ 04_ports/ 05_services/
  06_web/ 07_vulns/ 08_secrets/ 09_report/
- Output: target_profile.json (all initial intel)

PHASE 1 — PASSIVE RECONNAISSANCE & OSINT (Python subprocess)
─────────────────────────────────────────────────────────────
Run ALL of these concurrently (Python asyncio or Go goroutines
shelling out to Python workers):

  a) WHOIS: domain registration, registrar, nameservers, creation/
     expiry dates, registrant email/org (python-whois or whois CLI)
  b) DNS records: A, AAAA, CNAME, MX, NS, SOA, TXT (SPF, DKIM, DMARC),
     SRV, CAA, NAPTR (dnspython)
  c) Certificate Transparency: crt.sh API for all historical
     certificates → subdomains
  d) Shodan: query by domain AND IP (shodan Python SDK)
     → open ports, banners, vulnerabilities, geolocation, hostnames
  e) Censys: query by domain AND IP (censys Python SDK)
     → certificates, services, tags
  f) urlscan.io: search by domain → historical scans, screenshots,
     technologies, IPs
  g) VirusTotal: domain + IP lookup (API)
  h) GitHub code search: grep for target domain, IP, emails in
     public repos → exposed secrets, configs, API keys
  i) Pastebin / GitLab / Bitbucket search: same pattern
  j) Google Dorking: generate and execute (via SerpAPI or manual)
     - site:target.com inurl:admin
     - site:target.com filetype:pdf|doc|xls|zip|sql|bak
     - site:target.com intitle:"index of"
     - site:target.com inurl:php?
     - "target.com" password OR passwd OR credential
     - "target.com" api_key OR secret OR token
  k) LinkedIn / company employee enumeration (for phishing scope)
  l) Social media username check (sherlock-style, 300+ sites)
  m) HaveIBeenPwned: check any discovered emails
  n) DNS history: SecurityTrails, ViewDNS (if API key provided)
  o) DNS zone transfer attempt (AXFR) — passive, just try
  p) Reverse IP lookup: which other domains point to the same IP(s)
  q) ASN / BGP lookup: ipinfo.io, bgp.tools → network owner, range
  r) Shodan/Censys "neighbors": what else is on the same /24?

Output: 01_osint/osint_results.json, 01_osint/subdomains_passive.txt,
        01_osint/emails.txt, 01_osint/secrets_found.txt,
        01_osint/tech_stack.json, 01_osint/screenshots/

PHASE 2 — SUBDOMAIN ENUMERATION & ATTACK SURFACE DISCOVERY (Go)
────────────────────────────────────────────────────────────────
  a) Merge all passive subdomains from Phase 1
  b) Active DNS brute-force:
     - Wordlist: /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt
       + custom wordlist (user-provided)
     - Engine: async DNS (massdns-style, 1000+ rps)
     - Permutation: add numbers (0-99), common prefixes/suffixes
       (dev, staging, test, old, new, api, app, admin, portal, ...)
  c) Cloud bucket enumeration:
     - S3: s3scanner-style (list buckets by name permutation)
     - Azure Blob: check <name></name>.blob.core.windows.net
     - GCP: check <name></name>.storage.googleapis.com
     - DigitalOcean: check <name></name>.digitaloceanspaces.com
     - AWS: check <name></name>.s3.amazonaws.com
  d) Subdomain takeover detection:
     - For each CNAME, check if the target service is unclaimed
     - Services: Heroku, Ghost, Fastly, Shopify, GitHub Pages,
       Azure, S3, Heroku, Travis, Netlify, Bitbucket, etc.
  e) DNS resolution: resolve ALL subdomains → IPs
  f) Deduplicate: all subdomains + IPs into a single list
  g) New subdomain alerts: diff against previous workspace (if exists)

Output: 02_subdomains/all_subdomains.txt (deduped, sorted),
        02_subdomains/subdomain_ips.json (sub → [ips]),
        02_subdomains/cloud_assets.json,
        02_subdomains/takeovers.json,
        02_subdomains/new_subdomains.txt

PHASE 3 — HOST DISCOVERY & NETWORK SWEEP (Go)
──────────────────────────────────────────────
  a) For single IP / domain: skip (already known)
  b) For CIDR:
     - ICMP ping sweep (if raw socket available)
     - TCP SYN sweep on port 443, 80, 22, 3389 (fast liveness check)
     - ARP sweep (if on same L2, Linux only)
  c) For all discovered IPs:
     - Reverse DNS lookup
     - OS fingerprinting (via TCP/IP stack analysis — nmap -O style)
     - Geolocation (ipinfo.io, maxmind GeoLite2)
     - ASN / BGP info
  d) Build host inventory: IP → [subdomains, services, OS, geo, ASN]

Output: 03_hosts/live_hosts.txt, 03_hosts/host_inventory.json,
        03_hosts/arp_results.txt (if applicable)

PHASE 4 — PORT SCANNING & SERVICE DETECTION (Go)
─────────────────────────────────────────────────
  a) TCP scan:
     - Default: top 1000 ports (fast mode)
     - Full: 1-65535 (with --full-ports flag)
     - Engine: concurrent TCP connect (default) or SYN stealth
       (AF_PACKET, Linux, --syn flag)
     - Rate limiting: configurable (--rate N, default 1000 rps)
     - Retries: 2 per port, timeout 500ms
  b) UDP scan:
     - Top 100 UDP ports (DNS, SNMP, NTP, etc.)
     - Slower, run after TCP
  c) Service version detection:
     - Banner grabbing on all open ports (connect, read 1024 bytes,
       parse protocol signature)
     - TLS: extract certificate, cipher, protocol version
     - SSH: extract version string, host key algorithm
     - HTTP: extract Server header, X-Powered-By, title
     - SMTP: extract EHLO response
     - FTP: extract banner
     - For deeper detection: shell out to `nmap -sV -p <ports>`
  d) OS detection:
     - Shell out to `nmap -O -p <ports>` (uses nmap's OS fingerprint DB)
     - Cross-reference with TCP/IP stack analysis
  e) NSE script scan (vulnerability-aware):
     - Shell out to `nmap --script vuln -p <open_ports>`
     - Parse XML output
  f) If CIDR is large (> /24):
     - Optional: pre-scan with `masscan -p1-65535 --rate=10000` (C tool)
       to find open ports fast, then Go handles service detection

Output: 04_ports/ports.json (ip → [{port, proto, state, service, version}]),
        04_ports/nmap_full.xml, 04_ports/services.json,
        04_ports/os_fingerprints.json

PHASE 5 — SERVICE ENUMERATION & DEEP INSPECTION (Go + C tools)
───────────────────────────────────────────────────────────────
For each open service, run the appropriate enumeration:

  a) SSH (22):
     - Version, host key algorithm, ciphers
     - Check for: agent forwarding, X11 forwarding, empty passwords
     - Enumerate usernames (if enabled)
  b) HTTP/HTTPS (80, 443, 8080, 8443, 3000, 5000, ...):
     → Handled in Phase 6 (Web Recon)
  c) SMB (445):
     - Shell out to `enum4linux -a <ip>` (C tool)
     - Or: `smbclient -L //<ip> -N`
     - Extract: shares, users, groups, OS, domain, RID
  d) LDAP (389, 636):
     - Shell out to `ldapsearch -x -H ldap://<ip> -b '' -s base`
     - Extract: domain, rootDSE, naming contexts
  e) RDP (3389):
     - Banner grab, NLA check
     - Shell out to `nmap --script rdp-enum-encryption -p 3389`
  f) SNMP (161/UDP):
     - Shell out to `snmpwalk -v2c -c public <ip>`
     - Extract: system info, interfaces, users
  g) FTP (21):
     - Anonymous login check
     - List directories
  h) MySQL (3306), PostgreSQL (5432), MongoDB (27017), Redis (6379):
     - Version banner, unauthenticated access check
  i) DNS (53):
     - Zone transfer, DNSSEC, resolver info
  j) VNC (5900), Elasticsearch (9200), Docker (2375), etc.:
     - Banner grab, version, unauth check
  k) Custom/unknown ports:
     - Raw banner grab, hex dump, protocol guess

Output: 05_services/service_details.json (per-port deep info),
        05_services/smb_enum.txt, 05_services/ldap_enum.txt,
        05_services/snmp_walk.txt, 05_services/banners/

PHASE 6 — WEB APPLICATION RECON (Go + Python)
─────────────────────────────────────────────
For every HTTP/HTTPS host discovered:

  a) Technology fingerprinting:
     - Go: HTTP headers, response body regex (whatweb-style)
     - Detect: CMS (WordPress, Drupal, Joomla), framework
       (Laravel, Django, Rails, Spring), server (Nginx, Apache, IIS),
       WAF (Cloudflare, Akamai, AWS WAF, Imperva), CDN
  b) WAF detection:
     - Go: send test payloads, check for WAF signatures in response
     - Or: shell out to `wafw00f` (Python)
  c) Screenshot:
     - Python: Playwright headless browser → full-page PNG
     - Save to 06_web/screenshots/<subdomain></subdomain>.png
  d) Crawl & content discovery:
     - Go: concurrent crawler (katana-style)
       - Extract: all URLs, forms, parameters, endpoints
       - Parse: JavaScript files → extract URLs, API endpoints,
         secrets, internal hostnames
       - Respect: robots.txt (log but don't obey, unless --respect-robots)
       - Depth: configurable (default 3)
       - Max URLs: configurable (default 1000)
     - Go: directory brute-force (ffuf-style)
       - Wordlist: /usr/share/wordlists/seclists/Discovery/Web-Content/
       - Fuzz: directories, files, parameters
       - Detect: 200, 301, 302, 403, 500 (all interesting)
  e) API discovery:
     - Go: check common API paths (/api, /api/v1, /graphql, /swagger,
       /openapi.json, /docs, /redoc)
     - Go: parse Swagger/OpenAPI specs if found
     - Python: scrape JS for API calls (axios, fetch, XMLHttpRequest)
  f) Parameter discovery:
     - Go: fuzz common parameters (id, user, page, search, file, path,
       cmd, exec, eval, etc.)
     - Detect: reflection, error-based, time-based
  g) HTTP security headers:
     - Go: check HSTS, CSP, X-Frame-Options, X-Content-Type-Options,
       Referrer-Policy, Permissions-Policy
     - Score: 0-100
  h) TLS analysis:
     - Go: full TLS handshake, extract cert chain, check expiry,
       hostname match, weak ciphers, protocol version
     - Or: shell out to `testssl.sh` (shell) for deep analysis
  i) Subresource Integrity, CORS misconfiguration, clickjacking:
     - Go: automated checks
  j) Cookie security:
     - Go: check Secure, HttpOnly, SameSite flags
  k) robots.txt, sitemap.xml, .git, .env, .DS_Store, backup files:
     - Go: check common sensitive paths
     - Log findings (exposed .env = CRITICAL)

Output: 06_web/web_fingerprints.json, 06_web/crawl_results.json,
        06_web/directories_found.txt, 06_web/api_endpoints.json,
        06_web/js_analysis.json, 06_web/security_headers.json,
        06_web/tls_analysis.json, 06_web/screenshots/,
        06_web/parameters.json, 06_web/sensitive_files.json

PHASE 7 — VULNERABILITY SCANNING (Go orchestration + external tools)
────────────────────────────────────────────────────────────────────
  a) Nuclei (Go binary, shell out):
     - Run all templates against discovered URLs and IPs
     - `nuclei -u <url> -t nuclei-templates/ -severity critical,high,medium -jsonl`
     - Parse JSONL output → findings
  b) Nikto (Perl, shell out):
     - `nikto -h <url> -Format json -output nikto_<host>.json`
  c) SQLMap (Python, shell out):
     - For each discovered parameter:
       `sqlmap -u <url> --batch --level=2 --risk=1 --output-dir=07_vulns/sqlmap/`
     - Only if --deep flag is set (slow)
  d) WPScan (Ruby, shell out):
     - If WordPress detected: `wpscan --url <url> --json`
  e) Custom checks (Go):
     - Directory traversal (../../etc/passwd)
     - XSS (reflected, stored)
     - SSRF (internal IP resolution)
     - IDOR (sequential ID testing)
     - Auth bypass (common header/cookie tricks)
     - Default credentials (admin/admin, root/root, etc.)
  f) CVE matching:
     - Match detected service versions against NVD CVE database
     - (Download NVD JSON feed, filter by CVE, match version ranges)

Output: 07_vulns/nuclei_findings.jsonl, 07_vulns/nikto_results.json,
        07_vulns/sqlmap_results/, 07_vulns/wpscan_results.json,
        07_vulns/cve_matches.json, 07_vulns/custom_findings.json

PHASE 8 — SECRETS & SENSITIVE DATA EXTRACTION (Go + Python)
─────────────────────────────────────────────────────────────
  a) Go: scan all crawled content, headers, JS files for:
     - AWS keys (AKIA...), GCP keys, Azure keys
     - API tokens (Bearer, X-Api-Key, Authorization headers)
     - JWTs (decode, check exp, iss, sub)
     - Private keys (PEM headers: -----BEGIN RSA PRIVATE KEY-----)
     - Passwords in URLs (http://user:pass@host)
     - Internal IPs / hostnames
     - Database connection strings
  b) Python: NLP entity extraction from scraped text:
     - Email addresses, phone numbers, physical addresses
     - Person names, company names
     - Internal project names, codenames
  c) Go: check exposed files:
     - .env, .git/config, .htaccess, web.config, config.php
     - id_rsa, id_dsa, id_ecdsa, id_ed25519
     - *.sql, *.bak, *.old, *.swp
  d) Redact by default. --show-secrets to reveal.

Output: 08_secrets/secrets.json (redacted), 08_secrets/exposed_files.json

PHASE 9 — VULNERABILITY CORRELATION & RISK SCORING (Go)
────────────────────────────────────────────────────────
  a) Collect ALL findings from Phases 1-8
  b) Deduplicate: same CVE on same host = one finding
  c) Score each finding:
     - CRITICAL (P1): weight 4 — RCE, auth bypass, data exfil,
       exposed private keys, default creds on admin panel
     - HIGH (P2): weight 3 — SQLi, XSS (stored), SSRF, path traversal,
       known CVE with exploit available
     - MEDIUM (P3): weight 2 — XSS (reflected), CORS misconfig,
       info disclosure, weak TLS, missing security headers
     - LOW (P4): weight 1 — verbose errors, banner disclosure,
       old but unexploited software
     - INFO (P5): weight 0 — informational only
  d) Per-host risk score: sum of finding weights
  e) Overall target risk score: max host score + breadth (number of
     hosts with findings)
  f) MITRE ATT&CK mapping: tag each finding with relevant technique(s)
  g) Priority ranking: sort findings by (severity, exploitability,
     business impact)

Output: 09_report/risk_scores.json, 09_report/prioritized_findings.json

PHASE 10 — REPORTING & EXPORT (Go)
──────────────────────────────────
  a) Terminal report (default):
     - Color-coded (ANSI), structured by phase
     - Executive summary at top: target, risk score, top 5 findings
     - Per-section detail
     - Total time, packets sent, requests made
  b) HTML report (--html report.html):
     - Self-contained (inline CSS/JS), dark theme
     - Interactive: collapsible sections, filterable findings table,
       clickable URLs, embedded screenshots
     - Executive summary, methodology, findings, remediation
  c) JSON export (--json report.json):
     - Full structured data, schema-stable
     - Every finding with: id, severity, title, description,
       evidence (frames/URLs), MITRE ID, remediation, confidence
  d) CSV export (--csv findings.csv):
     - One row per finding for spreadsheet import
  e) PDF export (--pdf report.pdf):
     - Shell out to wkhtmltopdf on the HTML report
  f) Diff mode (--diff <previous_workspace>):
     - Compare two workspaces: new subdomains, new ports, new findings
     - Output: what changed between runs

═══════════════════════════════════════════════════════════════
CLI INTERFACE
═══════════════════════════════════════════════════════════════

reconx <target></target> [options]

Target:
  IP address:        reconx 192.168.1.1
  CIDR:              reconx 192.168.1.0/24
  Domain:            reconx example.com
  URL:               reconx https://app.example.com
  File:              reconx -f targets.txt

Phases (run all by default; select with --phases):
  --phases 0-10     Run all phases (default)
  --phases 0,1,2    Run only OSINT + subdomains
  --phases 4,5      Run only port scan + service enum
  --skip 1,2        Skip OSINT and subdomains (already have them)

Speed / Depth:
  --fast            Top 100 ports, top 1000 subdomains, shallow crawl
  --deep            Full 65535 ports, full subdomain brute, deep crawl,
                    sqlmap, wpscan, testssl.sh (SLOW)
  --rate N          Max requests/second (default 1000)
  --timeout N       Per-request timeout in ms (default 5000)
  --workers N       Concurrent workers (default 100)

Scanning:
  --syn             Use SYN stealth scanning (Linux, root required)
  --full-ports      Scan all 65535 TCP + top 100 UDP
  --udp             Include UDP scan
  --nmap-args "..." Pass extra args to nmap (for NSE, OS detection)
  --masscan         Pre-scan with masscan for large CIDRs (C tool)

Web:
  --crawl-depth N   Crawl depth (default 3)
  --max-urls N      Max URLs to crawl (default 1000)
  --respect-robots  Obey robots.txt (default: ignore)
  --screenshot      Take screenshots (requires Python + Playwright)
  --js-analysis     Deep JS analysis (extract endpoints, secrets)

OSINT:
  --shodan-key KEY  Shodan API key
  --censys-key KEY  Censys API key
  --vt-key KEY      VirusTotal API key
  --urlscan-key KEY urlscan.io API key
  --serp-key KEY    SerpAPI key (for Google dorking)
  --osint           Run full OSINT phase (default: on)
  --no-osint        Skip OSINT (faster, less data)

Vulnerability:
  --nuclei          Run Nuclei templates (default: on)
  --nikto           Run Nikto (default: on for web targets)
  --sqlmap          Run SQLMap on discovered parameters (SLOW)
  --wpscan          Run WPScan if WordPress detected
  --nvd             Match against NVD CVE database
  --cve-db PATH     Path to local NVD JSON feed

Output:
  --workspace DIR   Workspace directory (default: ./reconx_workspaces/<target></target>_<ts></ts>)
  --html FILE       Write HTML report
  --json FILE       Write JSON report
  --csv FILE        Write CSV findings
  --pdf FILE        Write PDF report
  --show-secrets    Do not redact secrets in output
  --diff DIR        Diff against previous workspace

General:
  --i-am-authorized Confirm you have written permission (REQUIRED)
  --config FILE     YAML config file for API keys, wordlists, etc.
  --verbose         Debug logging
  --quiet           Minimal output (errors only)
  --help            Show help
  --version         Show version

═══════════════════════════════════════════════════════════════
CONFIG FILE (reconx.yaml)
═══════════════════════════════════════════════════════════════

api_keys:
  shodan: "your-key"
  censys: "your-key"
  virustotal: "your-key"
  urlscan: "your-key"
  serpapi: "your-key"

wordlists:
  subdomains: "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
  directories: "/usr/share/wordlists/seclists/Discovery/Web-Content/common.txt"
  usernames: "/usr/share/wordlists/seclists/Discovery/Credentials/Username/username.lst"
  passwords: "/usr/share/wordlists/seclists/Discovery/Credentials/Passwords/Common-Credentials/top-1000.txt"

scanning:
  rate: 1000
  timeout_ms: 5000
  workers: 100
  ports: "top-1000"  # or "full" or "1-65535"
  udp_ports: "top-100"

web:
  crawl_depth: 3
  max_urls: 1000
  respect_robots: false
  user_agent: "Mozilla/5.0 (compatible; reconx/1.0)"

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
  wpscan: "/usr/local/bin/wpscan"
  testssl: "/usr/bin/testssl.sh"
  enum4linux: "/usr/bin/enum4linux"
  snmpwalk: "/usr/bin/snmpwalk"
  ldapsearch: "/usr/bin/ldapsearch"

═══════════════════════════════════════════════════════════════
ARCHITECTURE
═══════════════════════════════════════════════════════════════

reconx/
├── cmd/
│   └── reconx/
│       └── main.go              # CLI entry, cobra/viper
├── internal/
│   ├── orchestrator/
│   │   ├── engine.go            # Phase runner, dependency graph
│   │   ├── workspace.go         # Workspace init, file management
│   │   └── state.go             # Shared state between phases
│   ├── phase0_intake/
│   │   └── intake.go            # Target validation, resolution
│   ├── phase1_osint/
│   │   ├── osint.go             # Orchestrates Python subprocess
│   │   └── parse.go             # Parse Python JSON output
│   ├── phase2_subdomains/
│   │   ├── enumerate.go         # Async DNS brute (massdns-style)
│   │   ├── cloud.go             # S3, Azure, GCP bucket enum
│   │   ├── takeover.go          # Subdomain takeover detection
│   │   └── resolve.go           # Mass DNS resolution
│   ├── phase3_hosts/
│   │   ├── discovery.go         # Ping sweep, ARP, TCP sweep
│   │   └── fingerprint.go       # OS, geo, ASN
│   ├── phase4_ports/
│   │   ├── scanner.go           # TCP connect + SYN (AF_PACKET)
│   │   ├── udp.go               # UDP scan
│   │   ├── service.go           # Banner grab, version detect
│   │   └── nmap.go              # Shell out to nmap for -sV, -O, NSE
│   ├── phase5_services/
│   │   ├── ssh.go
│   │   ├── smb.go               # Shell out to enum4linux
│   │   ├── ldap.go              # Shell out to ldapsearch
│   │   ├── snmp.go              # Shell out to snmpwalk
│   │   ├── rdp.go
│   │   ├── ftp.go
│   │   ├── databases.go         # MySQL, PG, Mongo, Redis
│   │   └── generic.go           # Unknown port banner
│   ├── phase6_web/
│   │   ├── fingerprint.go       # Tech stack detection
│   │   ├── waf.go               # WAF detection
│   │   ├── crawler.go           # Concurrent web crawler
│   │   ├── brute.go             # Directory/file/param brute (ffuf-style)
│   │   ├── api.go               # API endpoint discovery
│   │   ├── js.go                # JS analysis (shell to Python)
│   │   ├── headers.go           # Security header checks
│   │   ├── tls.go               # TLS analysis
│   │   ├── sensitive.go         # .env, .git, backup files
│   │   └── screenshot.go        # Shell to Python Playwright
│   ├── phase7_vulns/
│   │   ├── nuclei.go            # Shell out to nuclei
│   │   ├── nikto.go             # Shell out to nikto
│   │   ├── sqlmap.go            # Shell out to sqlmap
│   │   ├── wpscan.go            # Shell out to wpscan
│   │   ├── custom.go            # Go-native checks (XSS, SSRF, etc.)
│   │   └── cve.go               # NVD CVE matching
│   ├── phase8_secrets/
│   │   ├── regex.go             # Key/token/password patterns
│   │   ├── nlp.go               # Shell to Python spaCy
│   │   └── files.go             # Exposed file checks
│   ├── phase9_scoring/
│   │   ├── correlate.go         # Dedup, merge, cross-reference
│   │   ├── score.go             # Risk scoring engine
│   │   └── mitre.go             # MITRE ATT&CK mapping
│   ├── phase10_report/
│   │   ├── terminal.go          # ANSI color output
│   │   ├── html.go              # HTML report (template)
│   │   ├── json.go              # JSON export
│   │   ├── csv.go               # CSV export
│   │   ├── pdf.go               # Shell to wkhtmltopdf
│   │   └── diff.go              # Workspace diffing
│   ├── scanner/
│   │   ├── tcp.go               # TCP connect scanner
│   │   ├── syn.go               # SYN stealth (AF_PACKET, Linux)
│   │   ├── udp.go               # UDP scanner
│   │   └── rate.go              # Rate limiter (token bucket)
│   ├── dns/
│   │   ├── resolver.go          # Async DNS resolver
│   │   ├── brute.go             # DNS brute-force engine
│   │   └── records.go           # Record type parsing
│   ├── httpx/
│   │   ├── client.go            # HTTP/1.1 + HTTP/2 client
│   │   ├── probe.go             # Single URL probe
│   │   └── fingerprint.go       # Tech fingerprinting
│   └── utils/
│       ├── ip.go                # IP/CIDR utilities
│       ├── domain.go            # Domain utilities
│       ├── dedup.go             # Deduplication
│       └── logger.go            # Structured logging
├── python/                        # Python subprocess modules
│   ├── osint/
│   │   ├── main.py              # Entry: python3 -m osint
│   │   ├── shodan.py
│   │   ├── censys.py
│   │   ├── crtsh.py
│   │   ├── urlscan.py
│   │   ├── github.py
│   │   ├── dorks.py
│   │   ├── whois.py
│   │   ├── social.py            # Username enumeration
│   │   ├── hibe.py              # HaveIBeenPwned
│   │   └── scrape.py            # General OSINT scraping
│   ├── js_analysis/
│   │   ├── main.py              # Entry: python3 -m js_analysis
│   │   └── extractor.py         # JS endpoint/secret extraction
│   ├── screenshot/
│   │   ├── main.py              # Entry: python3 -m screenshot
│   │   └── capture.py           # Playwright screenshot
│   └── nlp/
│       ├── main.py              # Entry: python3 -m nlp
│       └── entities.py          # spaCy entity extraction
├── wordlists/                     # Bundled wordlists (or symlinks to seclists)
├── templates/
│   ├── report.html              # HTML report template
│   └── nuclei/                  # Nuclei templates (or symlink)
├── go.mod
├── go.sum
├── Makefile
├── Dockerfile                     # Optional: containerized reconx
└── README.md

═══════════════════════════════════════════════════════════════
TECHNICAL REQUIREMENTS
═══════════════════════════════════════════════════════════════

- Go 1.22+, edition 2024
- CGO_ENABLED=0 for the Go binary (static, no libc dependency)
- Python 3.10+ for subprocess modules (Kali ships 3.11+)
- All external tools (nmap, masscan, nuclei, etc.) detected at
  startup; if missing, warn and skip that sub-phase gracefully
- Graceful degradation: if a phase fails (e.g., no Shodan key),
  log a warning and continue with remaining phases
- Rate limiting: token bucket per target, configurable global rate
- Context cancellation: Ctrl+C → clean shutdown, partial results
  saved to workspace
- Retry logic: exponential backoff for API calls, 2 retries for
  network probes
- No panics on malformed input (fuzz-test all parsers)
- Deterministic output: same input → same report (no timestamps
  in finding IDs, no random ordering)
- Structured logging: slog (Go 1.21+) with levels, --verbose for debug
- Testing: unit tests for all parsers, scorers, dedup logic;
  integration tests with mock HTTP servers and DNS stubs
- go vet, golangci-lint clean
- Shellcheck clean for any embedded shell commands

═══════════════════════════════════════════════════════════════
EXAMPLE RUN
═══════════════════════════════════════════════════════════════

$ reconx example.com --i-am-authorized --deep --html report.html --json report.json

═══════════════════════════════════════════════════════════
  RECONX — Automated Reconnaissance Engine v1.0
═══════════════════════════════════════════════════════════
  Target:    example.com (93.184.216.34)
  Mode:      DEEP (full ports, full subdomain brute, deep crawl)
  Workspace: ./reconx_workspaces/example.com_20261118_143200/

[PHASE 0] Target Intake ..................... DONE (0.3s)
[PHASE 1] Passive OSINT ..................... DONE (45.2s)
  → 2,341 subdomains (passive)
  → 47 emails found
  → 3 secrets found (GitHub code search)
  → Tech: Nginx/1.25, PHP/8.2, WordPress/6.5
[PHASE 2] Subdomain Enumeration ............. DONE (12.8s)
  → 4,523 total subdomains (after brute + cloud)
  → 3,891 resolved to IPs
  → 2 subdomain takeovers detected
  → 1 S3 bucket found (example-backup.s3.amazonaws.com)
[PHASE 3] Host Discovery .................... DONE (3.1s)
  → 12 unique IPs
  → OS: Linux (10), Windows (1), Unknown (1)
[PHASE 4] Port Scanning ..................... DONE (89.4s)
  → 47 open TCP ports across 12 hosts
  → 3 open UDP ports
  → Top services: HTTP (8), SSH (5), MySQL (2), Redis (1)
[PHASE 5] Service Enumeration ............... DONE (34.7s)
  → SMB: 2 shares found on 10.0.0.5
  → LDAP: domain=example.local, 47 users enumerated
  → SNMP: system info + 12 interfaces
  → Redis: UNAUTHENTICATED ACCESS on 10.0.0.9:6379 ⚠️
[PHASE 6] Web Application Recon ............. DONE (67.3s)
  → 8 web applications fingerprinted
  → 1,247 URLs crawled
  → 234 interesting directories found
  → 12 API endpoints discovered
  → 3 JS files with embedded secrets
  → 2 missing HSTS headers
  → 1 CORS misconfiguration
[PHASE 7] Vulnerability Scanning ............ DONE (156.2s)
  → Nuclei: 23 findings (2 critical, 5 high, 12 medium, 4 low)
  → Nikto: 8 findings
  → SQLMap: 1 confirmed SQLi (app.example.com/search?id=1)
  → WPScan: 3 plugins with known CVEs
  → CVE match: 7 additional CVEs for detected versions
[PHASE 8] Secrets Extraction ................ DONE (2.1s)
  → 5 AWS keys (1 active)
  → 2 JWTs (1 expired, 1 valid)
  → 1 exposed .env file (DB credentials)
  → 3 internal hostnames
[PHASE 9] Risk Scoring ...................... DONE (0.8s)
  → Overall Risk: CRITICAL (score 47/100)
  → Top host: 10.0.0.5 (score 23)
  → 38 total findings (2 critical, 8 high, 19 medium, 9 low)
[PHASE 10] Report Generation ................ DONE (1.4s)

═══════════════════════════════════════════════════════════
  EXECUTIVE SUMMARY
═══════════════════════════════════════════════════════════
  Target:       example.com
  Risk Score:   47/100 (CRITICAL)
  Findings:     38 (2 critical, 8 high, 19 medium, 9 low)
  Duration:     5m 33s
  Packets:      1.2M sent, 847K received
  Requests:     4,231 HTTP, 12,450 DNS

  TOP 5 FINDINGS:

1. [CRITICAL] Unauthenticated Redis on 10.0.0.9:6379
   → Data exfiltration, RCE via module load
   → MITRE: T1190 (Exploit Public-Facing Application)
2. [CRITICAL] SQL Injection in /search?id=
   → Full database compromise
   → MITRE: T1190
3. [HIGH]     Exposed .env with production DB credentials
   → MITRE: T1552.001 (Unsecured Credentials: Credentials
   In Files)
4. [HIGH]     Active AWS Access Key in GitHub repo
   → MITRE: T1552.001
5. [HIGH]     Subdomain takeover: old-blog.example.com →
   unclaimed Heroku app
   → MITRE: T1190

  Remediation priority: see report.html
═══════════════════════════════════════════════════════════
  Report: ./reconx_workspaces/example.com_20261118_143200/09_report/
  HTML:   report.html
  JSON:   report.json
═══════════════════════════════════════════════════════════

═══════════════════════════════════════════════════════════
IMPLEMENTATION ORDER
═══════════════════════════════════════════════════════════

Build in this order. Run `go test ./...` after each module.

1. go.mod, Makefile, CLI skeleton (cobra), workspace init
2. internal/scanner/ (TCP connect, then SYN via AF_PACKET)
3. internal/dns/ (async resolver, brute engine)
4. internal/httpx/ (client, probe, fingerprint)
5. Phase 0 (intake)
6. Phase 4 (port scan) — test against scanme.nmap.org
7. Phase 2 (subdomains) — test against a known domain
8. Phase 3 (host discovery)
9. Phase 5 (service enum) — shell out to nmap, enum4linux
10. Phase 6 (web recon) — crawler, brute, headers, TLS
11. Python modules: osint/ (Phase 1)
12. Phase 7 (vuln scanning) — shell out to nuclei, nikto
13. Phase 8 (secrets)
14. Phase 9 (scoring)
15. Phase 10 (reporting) — terminal first, then HTML, JSON
16. Orchestrator: wire all phases, dependency graph, state
17. Integration tests, fuzzing, documentation

═══════════════════════════════════════════════════════════
KALI LINUX SPECIFICS
═══════════════════════════════════════════════════════════

- Target: Kali Linux 2025.1+ (Debian 12 based)
- Wordlists: /usr/share/wordlists/seclists/ (pre-installed)
- External tools (pre-installed on Kali):
  nmap, masscan, nuclei, nikto, sqlmap, wpscan, enum4linux,
  snmpwalk, ldapsearch, testssl.sh, whatweb, wafw00f,
  subfinder, httpx, amass, dnsx, ffuf, katana, gau
- Python 3.11+ with: requests, httpx, beautifulsoup4, dnspython,
  python-whois, shodan, censys, playwright, spacy, pandas
- Install script (install.sh):
  - Check for all external tools, apt-get install missing ones
  - pip install Python dependencies
  - go build → /usr/local/bin/reconx
  - Install wordlists if missing
  - Create /etc/reconx/reconx.yaml config template
- Systemd service (optional): reconx@<target></target>.service for
  scheduled recon
- man page + bash completion (cobra generates both)

═══════════════════════════════════════════════════════════
BUILD THIS TOOL NOW.
═══════════════════════════════════════════════════════════
Start with go.mod, Makefile, and the CLI skeleton. Then implement
modules in the order specified. After each module, run `go test`.
The tool must compile with CGO_ENABLED=0 and produce a single
static binary. Python modules are invoked as subprocesses and
are NOT linked into the Go binary.
