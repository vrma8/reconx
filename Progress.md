# reconx — build progress

This is the current, consolidated state of the project. It supersedes the earlier
incremental notes and covers both the locally runnable baseline (PR #1) and the
follow-on capability pass on `arena/0e97e2e3-demo-11`.

## Current status

| Item | State |
| --- | --- |
| Codebase | Full ten-phase Go reconnaissance pipeline, authorization-gated and workspace-oriented. |
| Build | Single static `CGO_ENABLED=0` binary; Go 1.22.5, no external Go modules. |
| Local usability | `make fmt`, `make vet`, `make test`, `make test-race`, `make build`, Python helper tests and a local end-to-end run all pass. |
| Baseline commit | `a422e45`, merged into `main` as PR #1 (merge commit `de4d0f0`). |
| Extension commit | `692ca15` on `arena/0e97e2e3-demo-11`; 34 files changed, ~2,937 insertions. |
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

All new active probes remain behind the mandatory `--i-am-authorized` gate.
They use fixed payload lists, small target caps, short deadlines and explicit
opt-in flags. Sensitive-path checks use `HEAD` only and never download contents.

## Verification evidence

| Check | Result |
| --- | --- |
| `gofmt -l cmd internal` | Clean. |
| `GOPROXY=off make test` | Pass, all packages including new parser/check tests. |
| `GOPROXY=off make test-race` | Pass, no races. |
| `GOPROXY=off make vet` | Pass. |
| `GOPROXY=off make build` | Pass; static binary builds and `--version` works. |
| Python `compileall -q python` and `unittest discover` | Pass: 10 OSINT tests plus 1 NLP test. |
| End-to-end local HTTP fixture with all new opt-in checks | Phases 0, 4, 6, 7, 8, 9 and 10 `done`; 39 workspace artifacts; header/SRI/WAF/parameter/sensitive-path artifacts written; risk and reports generated. |
| Focused regression tests | OSINT ownership merge, bounded web checks, config keys, Nmap parser, service hex dumps, external parsers, secret patterns, scoring and report rendering. |

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

`--active-waf`, `--parameter-fuzzing`, `--sensitive-files` and `--active-checks`
are active probes; use them only inside the approved scope. Without them the
tool remains a passive/bounded assessment engine.

## Plan traceability

| Plan phase | Delivered implementation |
| --- | --- |
| 0 – intake | IP, IPv4 CIDR through `/16`, domain, URL and target-file parsing; mandatory authorization confirmation; DNS and reverse DNS resolution; DNS-suffix cloud provider hint; owner-only atomic workspace creation. |
| 1 – passive OSINT | Concurrent dependency-free worker for WHOIS, full DNS record set, CT, Shodan, Censys, urlscan, VirusTotal, GitHub/GitLab code search, SerpAPI dorks, Pastebin/GitLab/Bitbucket public-index search, structured public LinkedIn employee leads, HIBP, SecurityTrails/ViewDNS history and reverse-IP, ipinfo/bgp.tools ownership, bounded AXFR and Sherlock. Missing keys/tools self-skip without leaking credentials. |
| 2 – attack surface | Rate-limited async DNS with 1000-rps default; automatic SecLists top-5000 plus additive custom words and embedded fallback; numeric/environment permutations; complete name/IP/diff artifacts; target-derived S3/Azure/GCS/DigitalOcean checks; provider-CNAME takeover signatures and bounded HTTP verification. All operations reserve against `max_probes`. |
| 3 – hosts | CIDR TCP liveness, optional bounded ICMP, reverse DNS, live-host inventory and passive ASN/organization/country enrichment. ARP and raw-socket OS fingerprinting are not claimed. |
| 4 – ports | Top-1000, fast and full TCP modes; global rate limiter; retry/backoff; 100 responsive UDP probes; banner/TLS metadata; bounded protocol enrichment with hex dumps; optional masscan pre-scan parsed and TCP-verified. `--syn` reports its portable TCP-connect fallback. |
| 5 – services | Native banner/TLS and protocol metadata with bounded hex dumps; Nmap `-oX` normalized into services, versions, metadata and OS fingerprints; read-only SMB/enum4linux, LDAP rootDSE, SNMP system and FTP anonymous-check integrations. Raw tool output remains untrusted. |
| 6 – web | HTTP/1.1/HTTP/2 probing, TLS/cookie/security-header analysis, 0–100 header score, SRI, verified TLS policy assessment, passive and bounded active WAF signals, same-scope depth-aware crawler, forms/query/API discovery, bounded parameter probes, fixed-list sensitive-path `HEAD` checks, OpenAPI parsing, directory discovery, JS analysis, screenshots, wafw00f and testssl integrations. |
| 7 – vulnerabilities | Explicit Nuclei/Nikto/SQLMap/WPScan orchestration; Nuclei JSONL plus Nikto/WPScan/sqlmap normalization; opt-in bounded native checks with a hard budget; local NVD exact CPE/version matching; raw/custom/CVE artifacts. Intrusive tools remain opt-in. |
| 8 – secrets | Redacted AWS/Google/Azure/JWT/private-key/database/URL-credential/bearer/API-header/generic-secret detection; JWT public-claim metadata; internal IP/hostname indicators; exposed-file inventory; dependency-free extended entity extraction. Discovered values are never validated or used. |
| 9 – correlation | Stable content-derived finding IDs, dedupe, severity/breadth scoring, explainable exploitability/business-impact adjustments, per-asset scoring, MITRE fields and deterministic priority order. |
| 10 – reporting | ANSI terminal summary with activity counters and detail sections; JSON, CSV and self-contained dark HTML with filtering/collapsible sections and bounded embedded screenshots; optional PDF, workspace diff, complete phase rows and report/risk/finding artifacts. |

## Engineering controls

- Standard-library-first Go layout suitable for `CGO_ENABLED=0` static builds, with automatic SecLists discovery, additive custom wordlists and embedded fallbacks.
- Context cancellation, bounded worker pools, DNS and Phase-2 HTTP rate limiting, retry/backoff, probe budgets, atomic workspace writes, deterministic ordering and structured `slog` logging.
- API credentials travel from configuration/flags to optional Python workers through the process environment, never into URLs or reports.
- Optional tools are checked before the run, invoked without a shell, and missing tools only warn/skip their subphase.
- Unit, fuzz and in-process integration tests cover parsers, configuration, scanning, HTTP extraction/crawling, scoring, NVD matching, cloud candidates, external output parsing, CLI ordering and the workspace.

## Remaining deferred work

- Phase 3: ARP sweep, native TCP/IP-stack OS fingerprinting, active geolocation and raw-socket ICMP.
- Phase 4: privileged AF_PACKET SYN scanning, full SSH host-key algorithm enumeration and the plan's 500 ms default timeout (the portable default is 5 s).
- Phase 5: RDP/NLA encryption enumeration, UDP-to-SNMP pipeline linkage, native unauthenticated database checks, DNSSEC/resolver checks and robust unknown-protocol identification.
- Phase 6: timing-based WAF/injection detection and exhaustive wordlist-based sensitive-file discovery. Screenshot capture still needs the optional Playwright runtime.
- Phase 7: WPScan restriction to confirmed WordPress targets and full NVD version-range matching.
- Phase 8: a dedicated exhaustive exposed-file module.
- Phase 9: deeper CVE correlation beyond the local exact-version matcher.
- Phase 10: optional systemd scheduling.

These are intentional follow-on items; the finished work prioritizes a verified,
safe, usable local tool over unverified breadth.
