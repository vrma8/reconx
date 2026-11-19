# reconx — build progress

This is the current, consolidated state of the project. It supersedes the earlier
incremental notes and covers the locally runnable baseline (PR #1), the first
capability pass (PR #2) and the final completion pass on
`arena/fc1db183-demo-11`.

## Current status

| Item | State |
| --- | --- |
| Codebase | Full ten-phase Go reconnaissance pipeline, authorization-gated and workspace-oriented. |
| Build | Single static `CGO_ENABLED=0` binary; Go 1.22.5, no external Go modules. |
| Local usability | `make fmt`, `make vet`, `make test`, `make test-race`, `make build`, Python helper tests and a local end-to-end run all pass. |
| Baseline commit | `a422e45`, merged into `main` as PR #1 (merge commit `de4d0f0`). |
| Extension commits | `692ca15` / `9057f40`, merged as PR #2 (`f9dd015`). |
| Completion pass | `d84007f` on `arena/fc1db183-demo-11`; [PR #3](https://github.com/flamingo57/demo_11/pull/3) prepared for merge into `main`. |
| Safety model | Authorization flag required; active checks are opt-in, bounded and read-only; optional keys/tools degrade to warnings. |

The detailed capability/gap status is maintained in [`Phases.md`](Phases.md),
requirement traceability in [`docs/PLAN_COVERAGE.md`](docs/PLAN_COVERAGE.md), and
user-facing usage in [`README.md`](README.md).

## Work completed

### Baseline: make the project locally runnable (merged PR #1)

| Area | Change |
| --- | --- |
| CLI | `reconx <target> [options]` now works as documented. `normalizeArguments` moves options ahead of positional targets while preserving `--flag=value`, `-f targets.txt`, and `--` semantics. Added authorization-gating and target-first CLI tests. |
| Build | `make test` no longer combines `CGO_ENABLED=0` with `-race`; `make test-race` is a separate cgo-enabled target. |
| Web analysis | Fixed WordPress fingerprinting and per-page crawl depth; added regression coverage. |
| Reporting | Phase 10 rewrites final exports after the runner records its phase result, so all 11 phase rows appear in `report.json`; terminal top findings are severity-ordered. |
| Tests | In-process HTTP integration test covers phases 0, 4, 6, 8, 9 and 10, secret redaction and workspace artifacts. |

### Extended capability pass (current work)

| Phase | Capability added | Control / artifact |
| --- | --- | --- |
| 1/3 | Passive ipinfo/bgp.tools ownership merged into the host inventory as ASN, organization and country. | `--host-enrichment`; no additional network requests. |
| 4/5 | Native bounded protocol enrichment for SSH, SMTP EHLO, FTP features, Redis, Memcached, MySQL, PostgreSQL, MongoDB, VNC, RDP and HTTP, with a 512-byte hex dump. | `--service-details`; enriched `services.json`. |
| 4/5 | Nmap `-oX` output parsed into normalized services, versions, metadata and OS fingerprints without discarding native evidence. | `04_ports/os_fingerprints.json`; enriched `services.json`. |
| 6 | Explainable 0–100 header score, external SRI checks and verified TLS handshake assessment (hostname, chain, protocol, cipher). | `header_scores.json`, `sri_checks.json`, `tls_assessments.json`; passive/default-on. |
| 6 | Bounded WAF payload analysis, parameter reflection/error probes and fixed-list sensitive-path `HEAD` checks. | `waf_probes.json`, `parameter_probes.json`, `sensitive_paths.json`; max 3 hosts, 2 path seeds and 3 parameters per target. |
| 7 | Native bounded traversal, reflected XSS, SSRF, IDOR, auth-bypass and default-credential checks. Nikto, WPScan and sqlmap output normalized into findings. | `--active-checks` default off; hard 60-request budget; `tool_findings.json`. |
| 8 | Azure secret patterns, bearer/header API-key patterns and expanded dependency-free NLP entities (organizations, people, addresses, projects, codenames). | `secrets.json`, `entities.json`. |
| 9 | Exploitability and business-impact labels feed an explainable capped score adjustment; tool classifications are preserved. | `risk_scores.json`, `prioritized_findings.json`, CSV/HTML columns. |
| 10 | Activity counters, detailed terminal sections, interactive/filterable HTML, bounded embedded screenshots and screenshot references. | `report.json` `stats`/`screenshots`, `report.html`, terminal summary. |

### Final completion pass (current work)

| Phase | Capability added | Control / artifact |
| --- | --- | --- |
| 3/4 | Linux raw-socket ICMP sweep and raw-IP SYN scanner with capability checks and safe fallbacks. | `--icmp` / `--syn`; `ping` or TCP connect when CAP_NET_RAW is unavailable; SYN packets never complete a handshake. |
| 4 | SSH KEX/host-key/cipher algorithms, RDP negotiation metadata and 500 ms default timeout. | `--service-details`; `services.json`. |
| 5 | UDP/161-to-SNMP linkage, bounded DNSSEC-aware resolver query, read-only Redis/Memcached/PostgreSQL/public-API access indicators. | `05_services/dnssec.json`; enriched services. |
| 6 | Timing-aware WAF/parameter leads and capped built-in/custom sensitive-path wordlist. | `--active-waf`, `--parameter-fuzzing`, `--sensitive-files`, `--sensitive-wordlist`, `--max-sensitive-paths`; HEAD-only probes. |
| 7 | WordPress-only WPScan targeting and NVD `versionStart*`/`versionEnd*` range matching with ordered version tests. | Existing opt-in tool/CVE flags; `cve_matches.json`. |
| 8 | Deduplicated exposed-file inventory with source attribution and unique sensitive-path seeds. | `06_web/sensitive_paths.json`, `08_secrets/exposed_files.json`. |
| 10 | Optional systemd service/timer generator and example-config/CLI wiring. | `--systemd-unit`; `09_report/systemd/`. |

The default network timeout is now 500 ms as planned. Raw probes are attempted
only when explicitly requested; the fallback path is announced as a warning and
never silently claims a capability the host lacks.

All new active probes remain behind the mandatory `--i-am-authorized` gate.
They use fixed payload lists, small target caps, short deadlines and explicit
opt-in flags. Sensitive-path checks use `HEAD` only and never download contents.

## Verification evidence

| Check | Result |
| --- | --- |
| `gofmt -l cmd internal` | Clean. |
| `gofmt -l cmd internal` | Clean. |
| `GOPROXY=off go test ./...` / `GOPROXY=off make test` | Pass, all packages including the final raw-socket, DNSSEC, CPE-range, service, config and web checks. |
| `GOPROXY=off make test-race` | Pass, no races. |
| `GOPROXY=off make vet` | Pass. |
| `GOPROXY=off make build` | Pass; static binary builds and `--version` works. |
| Python `compileall -q python` and `unittest discover` | Pass: 10 OSINT tests plus 1 NLP test. |
| End-to-end local HTTP fixture (PR #2 pass) | Phases 0, 4, 6, 7, 8, 9 and 10 `done`; 39 workspace artifacts; header/SRI/WAF/parameter/sensitive-path artifacts written; risk and reports generated. |
| Final end-to-end local HTTP fixture | Phases 0, 3, 4, 5, 6, 7, 8, 9 and 10 `done`; MEDIUM risk (8/100), 7 findings, 1 host, 41 probes, 36 HTTP requests, 1 DNS query; 46 artifacts including DNSSEC, deduplicated sensitive-path/exposed-file, JSON/CSV/HTML and systemd files. |
| Focused regression tests | OSINT ownership merge, bounded web checks, config keys, Nmap parser, service hex dumps, external parsers, secret patterns, scoring, report rendering, SSH/RDP/PostgreSQL metadata, CPE ranges, DNSSEC encoding, raw checksums and systemd units. |

The sandbox originally had no Go compiler, so a Go 1.22.5 toolchain was
reproduced from upstream source. No dependency downloads were needed; all Go
verification used `GOPROXY=off`.

## Running locally

```bash
make fmt && make vet && make test && make build
./bin/reconx --version

# Only scan systems you are authorized to assess.
./bin/reconx http://127.0.0.1:8080/ --i-am-authorized --fast \
  --phases 0,4,6,8,9,10 --rate 500 --json /tmp/report.json
```

Extended run with the new opt-in capabilities:

```bash
./bin/reconx http://127.0.0.1:8080/ --i-am-authorized --fast \
  --phases 0,4,6,7,8,9,10 --rate 1000 \
  --service-details --header-score --sri-checks --tls-assessment \
  --active-waf --parameter-fuzzing --sensitive-files --active-checks \
  --json report.json --csv findings.csv --html report.html
```

`--active-waf`, `--parameter-fuzzing`, `--sensitive-files`, `--syn`, `--icmp`
and `--active-checks` are active probes; use them only inside the approved
scope. Without them the tool remains a passive/bounded assessment engine.

## Plan traceability

| Plan phase | Delivered implementation |
| --- | --- |
| 0 – intake | IP, IPv4 CIDR through `/16`, domain, URL and target-file parsing; mandatory authorization confirmation; DNS and reverse DNS resolution; DNS-suffix cloud provider hint; owner-only atomic workspace creation. |
| 1 – passive OSINT | Concurrent dependency-free worker for WHOIS, full DNS record set, CT, Shodan, Censys, urlscan, VirusTotal, GitHub/GitLab code search, SerpAPI dorks, Pastebin/GitLab/Bitbucket public-index search, structured public LinkedIn employee leads, HIBP, SecurityTrails/ViewDNS history and reverse-IP, ipinfo/bgp.tools ownership, bounded AXFR and Sherlock. Missing keys/tools self-skip without leaking credentials. |
| 2 – attack surface | Rate-limited async DNS with 1000-rps default; automatic SecLists top-5000 plus additive custom words and embedded fallback; numeric/environment permutations; complete name/IP/diff artifacts; target-derived S3/Azure/GCS/DigitalOcean checks; provider-CNAME takeover signatures and bounded HTTP verification. All operations reserve against `max_probes`. |
| 3 – hosts | CIDR TCP liveness, privileged raw-socket ICMP with `ping` fallback, reverse DNS, live-host inventory and passive ASN/organization/country enrichment. ARP and native stack OS fingerprinting remain external integrations. |
| 4 – ports | 500 ms default timeout; top-1000/fast/full modes; rate limiter; UDP probes; raw SYN with TCP fallback; SSH KEX/host-key/cipher enumeration; RDP metadata; banner/TLS protocol enrichment with hex dumps; optional masscan pre-scan. |
| 5 – services | Native metadata, RDP negotiation, UDP/161-to-SNMP linkage, bounded DNSSEC query, read-only Redis/Memcached/PostgreSQL/public-API indicators, Nmap XML normalization and explicit SMB/LDAP/SNMP/FTP integrations. |
| 6 – web | HTTP/1.1/HTTP/2 probing, TLS/header analysis, 0–100 header score, SRI, verified TLS policy, timing-aware WAF/parameter leads, capped custom/built-in sensitive-path `HEAD` checks, crawl/forms/API/OpenAPI/JS/directory discovery, screenshots, wafw00f and testssl. |
| 7 – vulnerabilities | Explicit opt-in external tools (WPScan only for confirmed WordPress), normalized output, bounded native checks, local NVD exact/ranged CPE matching with MITRE/business-impact metadata. |
| 8 – secrets | Redacted credential/secret detection, JWT claims, internal host indicators, deduplicated exposed-file inventory with source attribution and dependency-free entity extraction. Values are never validated or used. |
| 9 – correlation | Stable IDs, dedupe, exact/ranged CVE correlation and severity/breadth/exploitability/business-impact scoring with MITRE fields and deterministic priority. |
| 10 – reporting | ANSI summary, JSON/CSV/filterable HTML with bounded screenshots, optional PDF, workspace diff, complete phase rows and operator-reviewable systemd units. |

## Engineering controls

- Standard-library-first Go layout suitable for `CGO_ENABLED=0` static builds, with automatic SecLists discovery, additive custom wordlists and embedded fallbacks.
- Context cancellation, bounded worker pools, DNS and Phase-2 HTTP rate limiting, retry/backoff, probe budgets, atomic workspace writes, deterministic ordering and structured `slog` logging.
- API credentials travel from configuration/flags to optional Python workers through the process environment, never into URLs or reports.
- Optional tools are checked before the run, invoked without a shell, and missing tools only warn/skip their subphase.
- Unit, fuzz and in-process integration tests cover parsers, configuration, scanning, HTTP extraction/crawling, scoring, NVD matching, cloud candidates, external output parsing, CLI ordering and the workspace.

## Remaining platform-dependent limits

The portable, authorization-gated implementation covers the full ten-phase
workflow. The following items remain deliberately dependent on the host or on an
external integration rather than being silently faked:

- ARP and native TCP/IP-stack OS fingerprinting require platform-specific privileges/tools; Nmap `-O` remains the OS evidence source.
- Active geolocation/BGP-driven host discovery is not performed; passive ownership data is merged from Phase 1.
- Full NLA negotiation, arbitrary-protocol identification, exhaustive document metadata extraction and Playwright screenshot capture depend on optional external runtimes/tools.
- Systemd units are generated for operator review; installation and enabling remain an explicit host action.
- External tools and keyed OSINT sources still self-skip when their keys/binaries are absent.

Validation, not scope reduction, is the reason these limits are listed: no
capability is reported as complete if the local environment cannot support it.
