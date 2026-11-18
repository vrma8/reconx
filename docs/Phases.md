
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
* No host geolocation, ASN, or BGP enrichment in host inventory.
* ICMP uses the external `ping` command, not raw-socket probing.

**Phase 4**

* `--syn` still falls back to TCP connect; AF_PACKET SYN scanning is not implemented.
* Nmap OS/vulnerability XML is captured but not parsed into host/service data.
* Protocol-specific service metadata is incomplete: SSH host-key algorithms, SMTP EHLO capabilities, FTP details, and richer HTTP service correlation are not fully collected.
* The plan’s 500 ms default timeout differs from the current 5 s default.

**Phase 5**

* RDP/NLA/encryption enumeration is absent.
* UDP SNMP enumeration is not correctly linked from responsive UDP results into the service-enumeration pipeline.
* No native database unauthenticated-access checks for MySQL, PostgreSQL, MongoDB, Redis, Elasticsearch, Docker, VNC, etc.
* No DNSSEC/resolver-info/AXFR service checks.
* No raw hex dump or robust unknown-protocol identification.
* External tool output is captured but generally not parsed into normalized service details.

**Phase 6**

* WAF detection is passive signature matching or optional wafw00f; it does not perform the planned test-payload analysis.
* No parameter fuzzing/reflection/error/time detection.
* Missing Subresource Integrity checks.
* No header score from 0–100.
* TLS analysis lacks full hostname validation, chain validation, and weak-cipher/protocol policy assessment.
* Sensitive-file discovery depends on optional content discovery and does not comprehensively cover all planned paths.
* Screenshots require an externally installed Playwright runtime.
* HTML report does not embed screenshots.

**Phase 7**

* Missing native custom traversal, XSS, SSRF, IDOR, auth-bypass, and default-credential checks.
* Nikto, SQLMap, and WPScan output is not normalized into findings.
* WPScan is not restricted to confirmed WordPress targets.
* NVD matching is an exact local CPE/version matcher, not full NVD version-range matching.

**Phase 8**

* Missing Azure-specific credential patterns and several bearer/API-header patterns.
* NLP only extracts basic emails, phones, and internal hostnames; it does not deliver planned named entities, physical addresses, organizations, project names, or codenames.
* Exposed-file checks rely on HTTP content discovery rather than a dedicated exhaustive exposed-file module.

**Phase 9**

* Scoring does not incorporate exploitability or business impact beyond severity/breadth.
* CVE correlation is limited by the local exact-version matcher.

**Phase 10**

* Terminal output has no packets/request counters or full per-section detail.
* HTML is dark and self-contained, but not fully interactive/filterable/collapsible as planned.
* No screenshot embedding.
* No scheduled systemd integration.
