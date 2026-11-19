
### Current phase status

**Phase 1 — OSINT**

* The Phase-1 `Plan.md` workflow is implemented: complete listed DNS records, WHOIS, CT, Shodan/Censys domain-IP-neighbor calls, urlscan, VirusTotal, GitHub/GitLab code search, Pastebin/GitLab/Bitbucket public-index search, public LinkedIn employee leads, HIBP over discovered public emails, DNS history/reverse IP, ASN/BGP, bounded AXFR, and Sherlock integration.
* API-backed capabilities self-skip when the required user-supplied key is absent; Sherlock self-skips when it is not installed. Those unavailable external dependencies are operational conditions, not missing adapters. Raw credential-like snippets and banner values are redacted before persistence.

**Phase 2 — subdomain enumeration and attack surface**

* The Phase-2 `Plan.md` workflow is implemented: automatic SecLists top-5000 discovery plus additive custom words and an embedded fallback; 1000-rps-default async DNS; all required numeric/environment mutations; complete resolution/IP/diff artifacts; target-derived S3/Azure/GCS/DigitalOcean checks; and CNAME provider signatures plus HTTP verification for the listed takeover services.
* Every operation remains authorization-gated, rate-limited, and reserved against `max_probes`. Cloud candidates retain the documented user-configurable 500-candidate default; a 405/501 HEAD response receives one bounded GET fallback rather than an object download.

**Phase 3**

* ARP sweep is explicitly unavailable.
* No native TCP/IP stack OS fingerprinting.
* Passive ASN/organization/country ownership from Phase 1 is merged into the host inventory; active geolocation lookups and BGP-driven host discovery are not performed.
* ICMP uses the external `ping` command, not raw-socket probing.

**Phase 4**

* `--syn` still falls back to TCP connect; AF_PACKET SYN scanning is not implemented.
* Nmap `-oX` service/OS/vulnerability XML is parsed into normalized service names, versions, metadata and OS fingerprints.
* Opt-in native enrichment collects SSH software, SMTP EHLO, FTP features, Redis/Memcached/MySQL/PostgreSQL/MongoDB/VNC/RDP/HTTP metadata and a bounded 512-byte hex dump. SSH host-key algorithm enumeration remains partial.
* The plan’s 500 ms default timeout differs from the current portable 5 s default.

**Phase 5**

* RDP/NLA/encryption enumeration is absent; only bounded RDP TLS metadata is collected.
* UDP SNMP enumeration is not linked from responsive UDP results into the service-enumeration pipeline.
* No native unauthenticated-access checks for MySQL, PostgreSQL, MongoDB, Redis, Elasticsearch, Docker or VNC; only read-only metadata banners are gathered.
* No DNSSEC/resolver-info service checks beyond Phase 1's bounded AXFR worker.
* Bounded hex dumps and protocol guesses are available; robust identification of arbitrary unknown protocols is still best-effort.
* Nmap XML is normalized into service details. Other external tool output remains raw unless a format-specific parser exists.

**Phase 6**

* Passive WAF signatures and optional wafw00f are complemented by opt-in bounded harmless payload probes; timing-based WAF analysis is intentionally not implemented.
* Parameter reflection and error-pattern probes are implemented with fixed markers; timing-based injection detection is intentionally not implemented.
* Subresource Integrity checks and an explainable 0–100 header score are implemented.
* A verified TLS handshake pass reports hostname validity, chain trust, protocol version, cipher strength and issuer/expiry notes.
* A fixed high-signal sensitive-path `HEAD` list is implemented; exhaustive wordlist-based file discovery remains optional through content discovery.
* Screenshots still require the optional Playwright runtime; captured screenshots are embedded into the HTML report with a bounded size/count.

**Phase 7**

* Bounded native traversal, reflected-XSS, SSRF, IDOR, auth-bypass and default-credential checks are implemented behind `--active-checks` with a hard request budget.
* Nikto, WPScan and sqlmap output is normalized into tool-reported findings alongside Nuclei JSONL.
* WPScan is not yet restricted to confirmed WordPress targets.
* NVD matching is an exact local CPE/version matcher, not full NVD version-range matching.

**Phase 8**

* Azure storage/client secret, bearer token and API-key header patterns are implemented with redaction.
* The dependency-free NLP worker extracts emails, phones, internal hosts, organizations, people, physical addresses, project names and codenames.
* Exposed-file checks combine sensitive-path responses and HTTP content discovery; a dedicated exhaustive file module is not implemented.

**Phase 9**

* Exploitability and business-impact labels are added to findings and feed an explainable, capped score adjustment.
* CVE correlation is still limited by the local exact-version matcher.

**Phase 10**

* Terminal output includes activity counters, detailed host/web/warning sections and severity-ranked findings.
* HTML is dark, self-contained, filterable and collapsible.
* Captured screenshots are embedded with bounded size/count and referenced in `report.json`.
* Scheduled systemd integration is not implemented.
