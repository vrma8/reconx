# reconx plan traceability

This matrix maps the supplied `Plan.md` to the implementation. It is kept deliberately precise: a capability is marked **implemented** only when reconx performs it and stores an artifact; a third-party capability is **integrated** when reconx calls it only after the mandatory authorization gate and preserves the result; and **bounded** means an intentional rate, worker, result, or scope limit prevents an unbounded scan.

| Plan phase | Delivered implementation |
| --- | --- |
| 0 – intake | IP, IPv4 CIDR through `/16`, domain, URL and target-file parsing; mandatory authorization confirmation; DNS and reverse DNS resolution; DNS-suffix cloud provider hint; owner-only, atomic workspace creation. |
| 1 – passive OSINT | Concurrent dependency-free worker for WHOIS, A/AAAA/CNAME/MX/NS/SOA/TXT/SRV/CAA/NAPTR DNS, CT, Shodan domain/IP/neighbors with bounded redacted banner evidence, Censys domain/IP/neighbors, urlscan history/technology/bounded screenshot artifacts, VirusTotal domain/IP, GitHub/GitLab public-code metadata plus redacted secret indicators, SerpAPI dorks and Pastebin/GitLab/Bitbucket public-index search, structured public LinkedIn employee leads, HIBP for all bounded public email leads, SecurityTrails/ViewDNS history and reverse-IP, and ipinfo/bgp.tools ownership. Bounded AXFR and Sherlock username checks are enabled after `--i-am-authorized`; unavailable keys/tools degrade independently without leaking API keys or raw credential-like snippets. |
| 2 – attack surface | Passive-name merge; rate-limited async DNS with a 1000-rps default; automatic `/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt` use when installed plus an additive custom source and an embedded fallback; numeric `0–99` and dev/staging/test/old/new/api/app/admin/portal mutations; complete name-to-IP map including unresolved names; deduplicated IP inventory; previous-workspace diff; one-query CNAME takeover discovery and default provider-signature verification (Heroku, Ghost, Fastly, Shopify, GitHub Pages, Azure, regional S3, Travis, Netlify, Bitbucket); and bounded target-derived S3/Azure/GCS/DigitalOcean checks using provider virtual-host endpoints with HEAD-to-GET fallback when HEAD is explicitly unsupported. CNAME checks default to all discovered names and every Phase-2 DNS/HTTP operation is reserved against `max_probes` before dispatch. |
| 3 – hosts | CIDR TCP liveness, optional bounded ICMP echo sweep, reverse DNS, live-host and host inventory artifacts. Privileged ARP and packet-stack fingerprinting are retained as platform/tool integrations rather than fabricated. |
| 4 – ports | Top-1000, fast and full TCP modes; global token rate limiter; retry/backoff; 100 responsive UDP probes; banner/TLS metadata; optional masscan pre-scan parsed and TCP-verified; service/port/OS-artifact output. `--syn` reports its portable TCP-connect fallback when raw capability is unavailable. |
| 5 – services | Native banner/TLS data; optional nmap service/OS/vuln XML capture; explicit read-only SMB/enum4linux, LDAP rootDSE, SNMP system, and FTP anonymous-check integrations. Tool output stays raw/untrusted in the workspace. |
| 6 – web | HTTP/1.1/HTTP/2 probe, TLS/cookie/security-header analysis, technology/WAF signatures, same-scope crawler, forms/query/API discovery, OpenAPI parsing, optional directory discovery, JS endpoint analysis, screenshots, wafw00f and testssl integrations; all documented web artifacts. |
| 7 – vulnerabilities | Explicit Nuclei/Nikto/SQLMap/WPScan orchestration, Nuclei JSONL normalization, local NVD 2.0/legacy exact CPE-version matching, and raw/custom/CVE artifacts. Intrusive external tools remain opt-in. |
| 8 – secrets | Redacted AWS/Google/JWT/private-key/database/URL-credential/generic-secret detection; JWT public-claim metadata; internal IP/hostname indicators; exposed-file inventory; optional dependency-free entity extraction. Reconx never validates or uses discovered values. |
| 9 – correlation | Stable content-derived finding IDs, dedupe, severity and breadth scoring, per-asset scoring, MITRE fields and deterministic priority order. |
| 10 – reporting | ANSI terminal executive summary, JSON, CSV, self-contained dark HTML, optional PDF, workspace diff, report/risk/finding artifacts. |

## Technical practices enforced

- Standard-library-first Go layout suitable for `CGO_ENABLED=0` static builds, with automatic SecLists discovery, additive custom wordlists, and embedded fallbacks.
- Context cancellation, bounded worker pools, DNS and Phase-2 HTTP rate limiting, retry/backoff, probe budgets, atomic workspace writes, deterministic ordering and structured `slog` logging.
- API credentials only travel from configuration/flags to the optional Python process through its environment; they are not placed in URLs or reports.
- Optional tools are checked before the run, invoked without a shell, and missing tools only warn/skip their subphase.
- Unit tests and fuzz targets cover parsers, configuration, scanning, HTTP extraction, scoring, NVD matching, cloud candidates, and external output parsing. Python helpers have standard-library unit/smoke coverage.

## Environment validation note

The Arena workspace used for this change does not contain Go, so `make test`, `go vet`, `gofmt`, and static binary compilation must be run under Go 1.22+ after checkout. Python/helper syntax and tests, shell syntax, whitespace checks, and Go grammar parsing are run in this workspace.
