# reconx

`reconx` is an authorization-gated, workspace-oriented reconnaissance engine written in Go. It takes an IP, IPv4 CIDR (down to `/16`), domain, or HTTP(S) URL and produces a deterministic, portable workspace plus JSON, CSV, and HTML reports.

> **Use only with written authorization.** Every execution requires `--i-am-authorized`. Reconx applies a global probe rate, bounded worker pools, per-request deadlines, and a probe budget. It deliberately does not validate, use, or replay any credential-like material it discovers.

## Why this implementation is efficient

The plan's high-throughput goals are implemented without a dependency-heavy runtime:

- **Go standard library first:** no runtime Go dependencies, so `CGO_ENABLED=0` produces a single static binary.
- **Bounded worker pools:** DNS, TCP/UDP, HTTP, service and crawler workers reuse a bounded number of goroutines rather than allocating one goroutine per candidate.
- **One shared token-bucket ticker:** a scan's configured `--rate` is global across all TCP workers, preventing accidental rate multiplication.
- **Back-pressure and cancellation:** job queues are bounded and every phase observes `Ctrl+C`; partial, atomic workspace files are retained.
- **Deterministic data:** hosts, ports, URLs, findings, and IDs are normalized and sorted. Finding IDs are content hashes, never timestamps.
- **Graceful optional tooling:** Python and Kali tools are isolated subprocesses. An absent tool records a warning and does not abort the remaining phases.

The original plan calls for Cobra/Viper and SQLite. This build intentionally uses the Go standard library's `flag` package and atomic JSON workspace state instead: that removes transitive dependencies, reduces startup time, and keeps the CGO-free static-binary requirement. The documented CLI flags and YAML configuration shape are supported.

## Build and test

```bash
make fmt
make vet
make test
make build
# static binary: bin/reconx
```

The required toolchain is Go 1.22+ and Python 3.10+ only for the optional passive workers. The core scanner, resolver, HTTP probe, crawler, scorer, and reports use Go only. `./install.sh` builds and installs the binary; set `INSTALL_OPTIONAL_TOOLS=1` only on an approved Kali/Debian host to install optional external integrations through apt.

## Basic usage

```bash
# A bounded fast assessment
./bin/reconx https://app.example.com --i-am-authorized --fast \
  --rate 200 --html report.html --json report.json --csv findings.csv

# Explicit phase selection
./bin/reconx 192.0.2.0/24 --i-am-authorized --phases 0,3,4,9,10 --rate 100

# Read targets one per line. A separate workspace is created per target.
./bin/reconx -f targets.txt --i-am-authorized --fast
```

`--deep` enables all 65,535 TCP ports and Phase-2 permutations. Increase `max_subdomain_words` or `max_permutations` explicitly in the configuration when an authorized assessment needs a larger DNS scope; configured Phase-2 limits are never silently raised. The default probe ceiling is `300000`; scans that exceed it fail safely unless `--unsafe-large-scan` is given. Do not use that override to scan targets outside your explicit authorization.

## Pipeline

| Phase | Implemented baseline |
| --- | --- |
| 0 | Strict target parsing, CIDR cap, resolution, reverse DNS, workspace initialization |
| 1 | Concurrent bounded passive OSINT: full DNS record set, WHOIS, CT, Shodan/Censys/VT/urlscan, Shodan banner evidence, GitHub/GitLab code-search indicators, Pastebin/GitLab/Bitbucket public-index searches, structured public LinkedIn employee leads, HIBP for all discovered public emails, DNS history/reverse IP, ASN/BGP ownership, AXFR, and Sherlock integration. Each keyed source/tool self-skips when unavailable. |
| 2 | Globally rate-limited async DNS at the configured default 1000 rps, automatic SecLists top-5000 plus optional custom-wordlist merge, complete name/IP inventory, numeric/environment permutations, target-derived S3/Azure/GCS/DO probes with HEAD-to-GET fallback, previous-workspace diffs, and provider-CNAME takeover signature verification. All discovered CNAMEs are checked by default, subject to the authorized run's global probe budget. |
| 3 | CIDR liveness probe on 22/80/443/3389 and host inventory |
| 4 | Rate-limited TCP connect scanning with retry/backoff, top-100 responsive UDP probing, banner/TLS service metadata |
| 5 | Optional `nmap -sV --version-light` subprocess output capture |
| 6 | HTTP/1.1 + HTTP/2 probing, TLS data, fingerprints, forms/API endpoints, same-scope crawl, content discovery, cookie/CORS/header checks |
| 7 | Explicit opt-in external `nuclei`, `nikto`, `sqlmap`, and `wpscan`; Nuclei JSONL is normalized as tool-reported findings |
| 8 | Local credential/connection-string pattern detection and exposed-file artifacts with default redaction; no validation or use of values |
| 9 | Finding deduplication, stable IDs, severity/breadth risk score |
| 10 | Terminal summary plus workspace JSON/CSV/self-contained HTML/PDF (when `wkhtmltopdf` is installed) |

Reconx implements all ten pipeline phases. Phase 1 and Phase 2 run only after the mandatory authorization gate; source keys and missing local tools still self-skip without aborting the rest of the run. Use `--no-cloud-assets`, `--no-takeover-verify`, or the corresponding configuration values to suppress those Phase-2 HTTP checks when they are outside an approved scope. The portable core does not claim raw AF_PACKET privileges it does not have: `--syn` reports the TCP-connect fallback if a raw implementation is unavailable. Intrusive external tools remain explicit options; their raw output is preserved separately, and Nuclei results remain marked as tool-reported until manually validated. See [`docs/PLAN_COVERAGE.md`](docs/PLAN_COVERAGE.md) for requirement traceability and operational limits.

## Workspace

Each run creates:

```text
reconx_workspaces/<sanitized-target>_<utc-timestamp>/
├── target_profile.json
├── run_state.json
├── 01_osint/ … 08_secrets/
└── 09_report/
    ├── report.json
    ├── report.html
    ├── findings.csv
    ├── risk_scores.json
    └── prioritized_findings.json
```

Phase 2 additionally writes `02_subdomains/all_subdomains.txt`, `all_ips.txt`, `subdomain_ips.json`, `new_subdomains.txt`, `cloud_assets.json`, and `takeovers.json`. Use `--diff <workspace-or-report.json>` to produce `09_report/diff.json` listing new host names, open ports, and finding IDs.

## Configuration

The dependency-free config loader supports scalar values in the documented YAML structure:

```yaml
api_keys:
  shodan: "optional"
  censys_id: "optional"
  censys_secret: "optional"
  virustotal: "optional"
  urlscan: "optional"
  github: "optional"
  hibp: "optional"
  securitytrails: "optional"
  viewdns: "optional"
osint:
  # Both are bounded and run only after --i-am-authorized.
  axfr: true
  social_enum: true
wordlists:
  # Optional extra list; the installed SecLists top-5000 list is loaded
  # automatically and merged rather than replaced.
  subdomains: "/path/to/authorized-custom-subdomains.txt"
scanning:
  rate: 1000
  timeout_ms: 5000
  workers: 100
  retries: 2
  max_probes: 300000
  icmp: false
attack_surface:
  cloud_assets: true
  max_cloud_candidates: 500
  takeover_verify: true
  # Zero means every discovered CNAME, always subject to max_probes.
  max_takeover_checks: 0
  subdomain_permutations: true
  # Applied separately to the SecLists and custom sources.
  max_subdomain_words: 5000
  max_permutations: 10000
web:
  crawl_depth: 2
  max_urls: 500
  respect_robots: true
  user_agent: "reconx/1.0"
reporting:
  show_secrets: false
```

Run with `--config reconx.yaml`. Unsupported YAML constructs and unknown settings fail closed rather than being ignored.

## Optional integrations

- `python/osint` is a standard-library worker invoked with `python3 -m osint`. It uses source-specific keys only through its process environment, records source status/timing, and never writes keys or raw credential-like search snippets. Set `--python-dir` if the module is elsewhere.
- DNS history/reverse-IP data requires a SecurityTrails or ViewDNS key. Censys accepts either `censys` or the documented `censys_id`/`censys_secret` pair. AXFR and Sherlock username checks are bounded Phase-1 operations enabled after the authorization gate; set `osint.axfr: false` or `osint.social_enum: false` when an approved scope excludes them.
- `--nmap-service-scan`, `--nuclei`, `--nikto`, `--sqlmap`, `--wpscan`, and `--pdf` detect their local binaries and continue with a warning if unavailable.
- Do not put API keys on a shell command line in multi-user environments. Prefer a `0600` config file or a purpose-built external worker.

## Safety and data handling

- Only scan systems where you have explicit permission.
- Review crawl targets and external scanner templates before enabling them.
- Workspace files are created with owner-only permissions. Secret evidence is redacted by default; `--show-secrets` is intentionally explicit.
- Treat output as a lead, not proof. Verify all findings before remediation or disclosure.
