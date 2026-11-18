#!/usr/bin/env python3
"""Extract likely API endpoints and credential indicators from JavaScript.

The helper is intentionally passive: it reads already-fetched source from
stdin and never requests the URLs it finds.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import urllib.parse

CALL_RE = re.compile(r"(?is)(?:fetch|axios\.(?:get|post|put|delete|patch)|\.open)\s*\(?\s*['\"]([^'\"\s]+)")
URL_RE = re.compile(r"https?://[^'\"\s<>`]+")
SECRET_RE = re.compile(r"(?i)\b(?:api[_-]?key|secret|token|password)\s*[:=]\s*['\"]?([A-Za-z0-9_./+=-]{12,})")


def resolve(base: str, value: str) -> str | None:
    try:
        candidate = urllib.parse.urljoin(base, value)
        parsed = urllib.parse.urlparse(candidate)
    except ValueError:
        return None
    return candidate if parsed.scheme in {"http", "https"} else None


def main() -> int:
    parser = argparse.ArgumentParser(description="reconx passive JavaScript analyzer")
    parser.add_argument("--url", required=True)
    arguments = parser.parse_args()
    source = sys.stdin.read(2_000_000)
    endpoints = {resolve(arguments.url, value) for value in CALL_RE.findall(source) + URL_RE.findall(source)}
    endpoints.discard(None)
    indicators = []
    for value in SECRET_RE.findall(source):
        digest = hashlib.sha256(value.encode()).hexdigest()[:8]
        indicators.append({"preview": value[:4] + "…" + value[-4:], "sha256_prefix": digest})
    print(json.dumps({"url": arguments.url, "endpoints": sorted(endpoints), "secret_indicators": indicators[:100]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
