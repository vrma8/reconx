# reconx plan traceability

This matrix maps the supplied `Plan.md` to the implementation. It is kept deliberately precise: a capability is marked **implemented** only when reconx performs it and stores an artifact; a third-party capability is **integrated** when reconx calls it only after the mandatory authorization gate and preserves the result; and **bounded** means an intentional rate, worker, result, or scope limit prevents an unbounded scan.

| Plan phase | Delivered implementation |
| --- | --- |
| 0 – intake | IP, IPv4 CIDR through `/16`, domain, URL and target-file parsing; mandatory authorization confirmation; DNS and reverse DNS resolution; DNS-suffix cloud provider hint; owner-only, atomic workspace creation. |
| 1 – passive OSINT | Concurrent dependency-free worker for WHOIS, A/AAAA/CNAME/MX/NS/SOA/TXT/SRV/CAA/NAPTR DNS, CT, Shodan domain/IP/neighbors with bounded redacted banner evidence, Censys domain/IP/neighbors, urlscan history/technology/bounded screenshot artifacts, VirusTotal domain/IP, GitHub/GitLab public-code metadata plus redacted secret indicators, SerpAPI dorks and Pastebin/GitLab/Bitbucket public-index search, structured public LinkedIn employee leads, HIBP for all bounded public email leads, SecurityTrails/ViewDNS history and reverse-IP, and ipinfo/bgp.tools ownership. Bounded AXFR and Sherlock username checks are enabled after `--i-am-authorized`; unavailable keys/tools degrade independently without leaking API keys or raw credential-like snippets. |
| 2 – attack surface | Passive-name merge; rate-limited async DNS with a 1000-rps default; automatic `/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt` use when installed plus an additive custom source and an embedded fallback; numeric `0–99` and dev/staging/test/old/new/api/app/admin/portal mutations; complete name-to-IP map including unresolved names; deduplicated IP inventory; previous-workspace diff; one-query CNAME takeover discovery and default provider-signature verification (Heroku, Ghost, Fastly, Shopify, GitHub Pages, Azure, regional S3, Travis, Netlify, Bitbucket); and bounded target-derived S3/Azure/GCS/DigitalOcean checks using provider virtual-host endpoints with HEAD-to-GET fallback when HEAD is explicitly unsupported. CNAME checks default to all discovered names and every Phase-2 DNS/HTTP operation is reserved against `max_probes` before dispatch. |
| 3 – hosts | CIDR TCP liveness, privileged raw-socket ICMP echo sweep with `ping` fallback, reverse DNS, live-host and host inventory artifacts. Passive ASN/organization/country ownership from Phase 1 is merged into the inventory. ARP and native TCP/IP-stack OS fingerprinting remain explicit platform/tool integrations. |
| 4 – ports | Top-1000, fast and full TCP modes; 500 ms default timeout; global token rate limiter; retry/backoff; 100 responsive UDP probes; privileged raw-IP SYN scanning with TCP-connect fallback; banner/TLS metadata; SSH KEX/host-key/cipher algorithms; bounded protocol enrichment with metadata and 512-byte hex dumps; optional masscan pre-scan; service/port/OS artifacts. |
| 5 – services | Native banner/TLS and protocol metadata with bounded hex dumps; RDP negotiation encryption metadata; read-only unauthenticated-access indicators for Redis/Memcached/PostgreSQL/public HTTP APIs; UDP/161 linked to SNMP enumeration; one bounded DNSSEC-aware resolver query; Nmap `-oX` normalized into services/OS; explicit SMB/LDAP/SNMP/FTP integrations. Raw tool output is preserved alongside normalized data. |
| 6 – web | HTTP/1.1/HTTP/2 probe, TLS/cookie/security-header analysis, technology/WAF signatures with bounded status/signature/timing leads, same-scope crawler, forms/query/API discovery with reflection/error/timing probes, OpenAPI parsing, capped wordlist-based sensitive-path `HEAD` checks, header score, SRI, verified TLS assessment, directory/JS analysis, screenshots, wafw00f and testssl integrations. |
| 7 – vulnerabilities | Explicit Nuclei/Nikto/SQLMap/WPScan orchestration (WPScan only for confirmed WordPress targets); Nuclei JSONL plus Nikto/WPScan/sqlmap normalization; opt-in bounded native checks with a hard request budget; local NVD exact and ranged CPE matching with MITRE/business-impact metadata; raw/custom/CVE artifacts. Intrusive tools remain opt-in. |
| 8 – secrets | Redacted AWS/Google/Azure/JWT/private-key/database/URL-credential/bearer/API-header/generic-secret detection; JWT public-claim metadata; internal IP/hostname indicators; deduplicated exposed-file inventory with source attribution from web content, content discovery and sensitive-path probes; dependency-free extraction of organizations, people, addresses, projects and codenames. Reconx never validates or uses discovered values. |
| 9 – correlation | Stable content-derived finding IDs, dedupe, severity/breadth scoring, exact and ranged CVE correlation, explainable exploitability/business-impact adjustments, per-asset scoring, MITRE fields and deterministic priority order. |
| 10 – reporting | ANSI terminal executive summary with activity counters and detailed sections; JSON, CSV, self-contained dark HTML with filtering/collapsible sections and bounded embedded screenshots; optional PDF and operator-reviewable systemd service/timer units; workspace diff, report/risk/finding artifacts. |

## Technical practices enforced

- Standard-library-first Go layout suitable for `CGO_ENABLED=0` static builds, with automatic SecLists discovery, additive custom wordlists, and embedded fallbacks.
- Context cancellation, bounded worker pools, DNS and Phase-2 HTTP rate limiting, retry/backoff, probe budgets, atomic workspace writes, deterministic ordering and structured `slog` logging.
- API credentials only travel from configuration/flags to the optional Python process through its environment; they are not placed in URLs or reports.
- Optional tools are checked before the run, invoked without a shell, and missing tools only warn/skip their subphase.
- Unit tests and fuzz targets cover parsers, configuration, scanning, HTTP extraction, scoring, NVD matching, cloud candidates, and external output parsing. Python helpers have standard-library unit/smoke coverage.

## Environment validation note

The original workspace did not contain a Go compiler, so a Go 1.22.5 toolchain
was reproduced from upstream source inside the sandbox. All Go checks below
were executed with `GOPROXY=off` after that toolchain was available: `gofmt`,
`go vet`, `make test`, `make test-race`, `make build`, and an end-to-end local
HTTP fixture run with the new opt-in checks enabled. Python helpers were checked
with `compileall` and `unittest discover`.
