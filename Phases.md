
### Current phase status

**Phase 1 — OSINT**

* The Phase-1 `Plan.md` workflow is implemented: complete listed DNS records, WHOIS, CT, Shodan/Censys domain-IP-neighbor calls, urlscan, VirusTotal, GitHub/GitLab code search, Pastebin/GitLab/Bitbucket public-index search, public LinkedIn employee leads, HIBP over discovered public emails, DNS history/reverse IP, ASN/BGP, bounded AXFR, and Sherlock integration.
* API-backed capabilities self-skip when the required user-supplied key is absent; Sherlock self-skips when it is not installed. Those unavailable external dependencies are operational conditions, not missing adapters. Raw credential-like snippets and banner values are redacted before persistence.

**Phase 2 — subdomain enumeration and attack surface**

* The Phase-2 `Plan.md` workflow is implemented: automatic SecLists top-5000 discovery plus additive custom words and an embedded fallback; 1000-rps-default async DNS; all required numeric/environment mutations; complete resolution/IP/diff artifacts; target-derived S3/Azure/GCS/DigitalOcean checks; and CNAME provider signatures plus HTTP verification for the listed takeover services.
* Every operation remains authorization-gated, rate-limited, and reserved against `max_probes`. Cloud candidates retain the documented user-configurable 500-candidate default; a 405/501 HEAD response receives one bounded GET fallback rather than an object download.

**Phase 3**

* ARP sweep is explicitly unavailable in the portable CGO-free build.
* No native TCP/IP-stack OS fingerprinting; Nmap `-O` remains the OS evidence source when enabled.
* Passive ASN/organization/country ownership from Phase 1 is merged into the host inventory; active geolocation lookups and BGP-driven host discovery are not performed.
* ICMP echo discovery uses a privileged raw-socket sweep when CAP_NET_RAW is available and falls back to the installed `ping` command otherwise.

**Phase 4**

* `--syn` now uses a bounded raw-IP TCP SYN scanner when CAP_NET_RAW is available, with a clear warning and TCP-connect fallback when it is not. The scanner sends SYN packets only and never completes a handshake.
* Nmap `-oX` service/OS/vulnerability XML is parsed into normalized service names, versions, metadata and OS fingerprints.
* Native enrichment collects SSH software plus KEX/host-key/cipher algorithms, SMTP EHLO, FTP features, Redis/Memcached/MySQL/PostgreSQL/MongoDB/VNC/RDP/HTTP metadata and a bounded 512-byte hex dump.
* The plan's 500 ms default timeout is now the portable default; operators can override it with `--timeout`.

**Phase 5**

* RDP negotiation metadata reports SSL/HYBRID/RDSTLS support; full NLA session negotiation remains an external-tool integration.
* Responsive UDP/161 results are linked into the service inventory so the read-only `snmpwalk` integration can run in Phase 5.
* Read-only unauthenticated-access indicators are recorded for Redis `INFO`, Memcached `stats`, PostgreSQL startup without credentials, and public Elasticsearch/Docker HTTP APIs. MySQL/MongoDB/VNC remain banner/version-only.
* A single DNSSEC-aware DNSKEY query records the AD bit, DNSKEY/RRSIG counts and resolver notes for domain targets.
* Bounded hex dumps and protocol guesses are available; robust identification of arbitrary unknown protocols is still best-effort.
* Nmap XML is normalized into service details. Other external tool output remains raw unless a format-specific parser exists.

**Phase 6**

* Passive WAF signatures and optional wafw00f are complemented by opt-in bounded payload probes with signature, status and timing-lead signals.
* Parameter reflection, error-pattern and bounded timing-delta probes are implemented; timing results are leads, not confirmed injection.
* Subresource Integrity checks and an explainable 0–100 header score are implemented.
* A verified TLS handshake pass reports hostname validity, chain trust, protocol version, cipher strength and issuer/expiry notes.
* Sensitive-path checks use a built-in high-signal list and an optional/auto-detected wordlist, capped by `--max-sensitive-paths`, with `HEAD` requests only.
* Screenshots still require the optional Playwright runtime; captured screenshots are embedded into the HTML report with a bounded size/count.

**Phase 7**

* Bounded native traversal, reflected-XSS, SSRF, IDOR, auth-bypass and default-credential checks are implemented behind `--active-checks` with a hard request budget.
* Nikto, WPScan and sqlmap output is normalized into tool-reported findings alongside Nuclei JSONL.
* WPScan runs only for targets with confirmed WordPress fingerprints.
* NVD matching supports exact CPE versions and NVD `versionStart*`/`versionEnd*` ranges with a bounded, dependency-free version comparator; exotic vendor-specific version schemes remain best-effort.

**Phase 8**

* Azure storage/client secret, bearer token and API-key header patterns are implemented with redaction.
* The dependency-free NLP worker extracts emails, phones, internal hosts, organizations, people, physical addresses, project names and codenames.
* Exposed-file inventory combines sensitive-path responses, content-discovery results and web responses into one deduplicated artifact with source attribution. Document metadata extraction from downloaded files remains outside the portable core.

**Phase 9**

* Exploitability and business-impact labels are added to findings and feed an explainable, capped score adjustment.
* CVE correlation uses exact and ranged CPE matches, adds MITRE technique tags and business-impact metadata, and deduplicates by CVE/product/asset.

**Phase 10**

* Terminal output includes activity counters, detailed host/web/warning sections and severity-ranked findings.
* HTML is dark, self-contained, filterable and collapsible.
* Captured screenshots are embedded with bounded size/count and referenced in `report.json`.
* Optional systemd service/timer units are written for operator review; installing and enabling them remains an explicit host action.
